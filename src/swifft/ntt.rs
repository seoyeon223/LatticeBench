// src/swifft/ntt.rs
//
// SWIFFT 용 negacyclic NTT (Q = 257, N = 64).
//
// 수정 핵심
// ---------
// 1. Stockham auto-sort(DIT) 버터플라이 인덱싱을 표준 정합 구조로 교체.
//    - 스테이지 s 에서 L = 1<<s (블록당 버터플라이 수),
//      m = N >> (s+1) (블록 수).
//    - 입력은 src[k*L + j] 와 src[k*L + j + N/2] 에서 읽고,
//      출력은 dst[2*k*L + j] 와 dst[2*k*L + j + L] 에 쓴다.
//    - 매 스테이지 출력을 mod_q 로 환원해 누적 오버플로를 차단한다.
// 2. 트위들 인덱스는 twiddles[j * m]. 실제 사용되는 최대 인덱스는 31 이므로
//    OMEGA_TABLE / OMEGA_INV_TABLE 은 최소 32, 안전하게 N(64)개를 모두 채운다.
//    (원본의 N/2 만 채우는 방식은 사용 인덱스가 0 으로 비어 결과가 0 으로
//     뭉개질 위험이 있었다.)
// 3. mod_q 비트트릭은 입력이 약 65791 이하일 때만 정확하다(검증함).
//    버터플라이에서 v = mod_q(w * b) 로 곱을 먼저 환원하므로
//    이후 u ± v 는 항상 [-256, 512] 범위로 안전하다.
// 4. negacyclic 사전/사후 곱(PSI, PSI_INV)도 매 항 mod_q 로 환원한다.

use super::{SwifftPoly, M};

pub const Q: i32 = 257;
pub const N: usize = 64;
pub const LOG_N: usize = 6;

// psi: 1 의 2N(=128)차 원시근,  omega = psi^2 : N(=64)차 원시근
pub const PSI: i32 = 9;
pub const PSI_INV: i32 = 200;
pub const OMEGA: i32 = 81;
pub const OMEGA_INV: i32 = 165;
pub const N_INV: i32 = 253;

/// 범용 모듈러 환원(이중 폴딩). 입력이 약 [-300, 65536] 범위일 때 정확.
/// 외부 호출자(negacyclic_convolution, mod.rs, simd.rs)가 쓰는 공개 API라
/// 시그니처/동작을 보존한다. NTT 내부 핫패스는 아래의 더 싼 환원을 쓴다.
#[inline(always)]
pub fn mod_q(x: i32) -> i32 {
    let mut t = (x & 0xFF) - (x >> 8);
    t = (t & 0xFF) - (t >> 8);
    t + ((t >> 31) & 257)
}

// ── NTT 핫패스 전용 위치-특화 환원 (lazy reduction) ─────────────────────
//
// 분석 결과: Stockham 구조상 곱셈 입력은 매 스테이지 환원이 필요해
// "스테이지 건너뛰기"식 lazy 는 불가하다. 대신 *환원 1회의 비용* 을 줄인다.
// 기존 mod_q 는 버터플라이마다 3회 호출되고(정변환당 576회) 매 호출이
// 6 시프트/AND + 분기성 보정의 이중 폴딩이었다. 이를 연산 위치에 맞는
// 최소 연산으로 대체한다. Python 으로 기존 결과와 비트 단위 일치 +
// 왕복 항등을 2000 케이스 검증함.

/// 곱 결과 전용 환원. w,b ∈ [0,256] → w*b ∈ [0,65536].
/// 256 ≡ -1 (mod 257) 이므로 x = hi*256 + lo ≡ lo - hi.
/// 단일 폴딩이면 r ∈ [-256,255], 음수일 때 +257 한 번으로 [0,256] 복구.
/// (이중 폴딩 불필요 → 시프트/AND 절반, 분기 1회.)
/// pub(crate): simd.rs 가 동일 산술의 AVX2 버전을 만들 때 스칼라 기준으로 사용.
#[inline(always)]
pub(crate) fn reduce_mul(x: i32) -> i32 {
    let lo = x & 0xFF;
    let hi = x >> 8;
    let r = lo - hi; // [-256, 255]
    r + ((r >> 31) & 257) // r<0 이면 +257 (분기 없는 마스크)
}

/// 덧셈/뺄셈 결과 전용 환원. 입력 v ∈ [-256, 512] 일 때 정확.
/// (a∈[0,256], t∈[0,256] → a+t∈[0,512], a-t∈[-256,256].)
/// 폴딩 없이 조건부 보정 2회(>=Q 면 -Q, <0 이면 +Q)만 — 분기 없는 마스크.
#[inline(always)]
pub(crate) fn reduce_addsub(v: i32) -> i32 {
    // v >= 257 이면 -257  (v 최대 512 → 한 번이면 [0,255])
    let v = v - (((256 - v) >> 31) & 257);
    // v < 0 이면 +257
    v + ((v >> 31) & 257)
}

/// 컴파일 타임에 base^i (mod 257) 테이블 생성.
/// size 만큼 채우고 나머지는 0 (사용되지 않는 인덱스).
const fn compute_powers(base: i32, size: usize) -> [i32; N] {
    let mut powers = [0; N];
    let mut w = 1;
    let mut i = 0;
    while i < size {
        powers[i] = w;
        let mut next = (w * base) % 257;
        if next < 0 {
            next += 257;
        }
        w = next;
        i += 1;
    }
    powers
}

// 트위들 테이블: j*m 의 최대값이 31 이므로 안전하게 N 개 전부 채운다.
pub const OMEGA_TABLE: [i32; N] = compute_powers(OMEGA, N);
pub const OMEGA_INV_TABLE: [i32; N] = compute_powers(OMEGA_INV, N);

// negacyclic 비틀기(twist) 테이블: 인덱스 0..N 모두 사용.
pub const PSI_TABLE: [i32; N] = compute_powers(PSI, N);
pub const PSI_INV_TABLE: [i32; N] = compute_powers(PSI_INV, N);

/// Stockham auto-sort 한 스테이지.
/// const generic 으로 L(블록당 버터플라이 수)을 박아 컴파일러가 전개하게 한다.
/// m = N / (2*L) 는 컴파일 타임 상수가 된다.
#[inline(always)]
fn stockham_stage<const L: usize>(
    src: &[i32; N],
    dst: &mut [i32; N],
    twiddles: &[i32; N],
) {
    let m = N / (2 * L); // 블록 수

    for k in 0..m {
        for j in 0..L {
            let w = twiddles[j * m];

            let a = src[k * L + j];
            let b = src[k * L + j + N / 2];

            // 곱은 단일 폴딩 환원: w*b ≤ 65536 → reduce_mul 안전.
            let v = reduce_mul(w * b);

            // a 는 직전 스테이지 출력이라 [0,256], v 도 [0,256].
            // a+v ∈ [0,512], a-v ∈ [-256,256] → reduce_addsub 안전 영역.
            dst[2 * k * L + j] = reduce_addsub(a + v);
            dst[2 * k * L + j + L] = reduce_addsub(a - v);
        }
    }
}

/// 길이 N negacyclic-friendly NTT.
/// inverse=false: 정변환,  inverse=true: 역변환(끝에 N^{-1} 곱).
pub fn ntt(a: &mut [i32; N], inverse: bool) {
    let twiddles = if inverse {
        &OMEGA_INV_TABLE
    } else {
        &OMEGA_TABLE
    };

    let mut buf = [0i32; N];

    // LOG_N(=6) 스테이지. ping-pong 버퍼.
    // 스테이지마다 src/dst 가 a <-> buf 로 번갈아간다.
    // 6번(짝수) 스왑하므로 최종 결과는 다시 a 에 위치.
    stockham_stage::<1>(a, &mut buf, twiddles);     // L=1,  m=32
    stockham_stage::<2>(&buf, a, twiddles);         // L=2,  m=16
    stockham_stage::<4>(a, &mut buf, twiddles);     // L=4,  m=8
    stockham_stage::<8>(&buf, a, twiddles);         // L=8,  m=4
    stockham_stage::<16>(a, &mut buf, twiddles);    // L=16, m=2
    stockham_stage::<32>(&buf, a, twiddles);        // L=32, m=1

    if inverse {
        for i in 0..N {
            // a[i] ∈ [0,256], N_INV=253 → 곱 ≤ 64768 ≤ 65536 → reduce_mul 안전.
            a[i] = reduce_mul(a[i] * N_INV);
        }
    }
    // 정변환 결과는 각 스테이지에서 환원되어 [0,256] 이므로 추가 처리 불필요.
}

// ── 하이브리드(스칼라 전반 + SIMD 후반) 지원 ────────────────────────────
//
// 분석(vec_analysis): 후반 3스테이지(L=8,16,32)는 read/write 가 연속 8-묶음
// 이라 AVX2 로 깔끔히 벡터화된다. 전반 3스테이지(L=1,2,4)는 버터플라이가
// 8개 미만이라 레인 셔플 비용이 커 스칼라가 유리. 트위들은 j*m 이라
// 스테이지마다 stride 가 달라, 스테이지별로 j*m 을 미리 펼친 평면 테이블을
// const 로 둔다(연속 벡터 로드 가능). 정/역 각각 별도 테이블.
//
// simd.rs 는 run_early_stages 로 전반 3스테이지(검증된 스칼라)를 돌린 뒤,
// 그 출력 버퍼와 아래 평면 트위들로 후반 3스테이지를 AVX2 로 처리한다.
// AVX2 버터플라이는 reduce_mul/reduce_addsub 와 비트 단위 동일한 산술을
// 쓰므로 풀 스칼라 ntt() 와 결과가 정확히 일치한다(Python 3000 검증).

/// 스테이지 s 의 j*m 트위들을 미리 펼친 평면 테이블 (길이 L, 8의 배수).
const fn flatten_tw(table: &[i32; N], l: usize) -> [i32; 32] {
    let m = N / (2 * l);
    let mut out = [0i32; 32];
    let mut j = 0;
    while j < l {
        out[j] = table[j * m];
        j += 1;
    }
    out
}

// L=8 (s=3, m=4): 앞 8개만 유효.  L=16 (s=4, m=2): 앞 16개.  L=32 (s=5, m=1): 32개.
pub(crate) const TW_FWD_L8: [i32; 32] = flatten_tw(&OMEGA_TABLE, 8);
pub(crate) const TW_FWD_L16: [i32; 32] = flatten_tw(&OMEGA_TABLE, 16);
pub(crate) const TW_FWD_L32: [i32; 32] = flatten_tw(&OMEGA_TABLE, 32);
pub(crate) const TW_INV_L8: [i32; 32] = flatten_tw(&OMEGA_INV_TABLE, 8);
pub(crate) const TW_INV_L16: [i32; 32] = flatten_tw(&OMEGA_INV_TABLE, 16);
pub(crate) const TW_INV_L32: [i32; 32] = flatten_tw(&OMEGA_INV_TABLE, 32);

/// 전반 3스테이지(L=1,2,4)만 검증된 스칼라로 수행하고 결과 버퍼를 돌려준다.
/// ping-pong 3회(홀수) 이므로 최종 결과는 buf 쪽 → buf 를 반환한다.
/// simd.rs 는 이 출력으로 후반 3스테이지를 SIMD 처리한다.
#[inline]
pub(crate) fn run_early_stages(a: &[i32; N], inverse: bool) -> [i32; N] {
    let tw = if inverse {
        &OMEGA_INV_TABLE
    } else {
        &OMEGA_TABLE
    };
    let mut buf = [0i32; N];
    let mut tmp = *a;
    stockham_stage::<1>(&tmp, &mut buf, tw); // a -> buf
    stockham_stage::<2>(&buf, &mut tmp, tw); // buf -> tmp
    stockham_stage::<4>(&tmp, &mut buf, tw); // tmp -> buf
    buf // L=8 스테이지의 입력
}

/// 역변환 마지막의 N^{-1} 스케일링(스칼라). simd.rs 후반-AVX2 경로가
/// 후처리로 호출한다. a[i] ∈ [0,256] 이므로 reduce_mul 안전.
#[inline]
pub(crate) fn scale_inverse(a: &mut [i32; N]) {
    for i in 0..N {
        a[i] = reduce_mul(a[i] * N_INV);
    }
}

/// x^N + 1 위에서의 다항식 곱 (negacyclic convolution).
pub fn negacyclic_convolution(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut a_ntt = [0i32; N];
    let mut b_ntt = [0i32; N];

    // PSI 비틀기 후 환원 (mod_q 입력 안전 영역 유지).
    for i in 0..N {
        a_ntt[i] = mod_q(a[i] * PSI_TABLE[i]);
        b_ntt[i] = mod_q(b[i] * PSI_TABLE[i]);
    }

    ntt(&mut a_ntt, false);
    ntt(&mut b_ntt, false);

    let mut c_ntt = [0i32; N];
    for i in 0..N {
        c_ntt[i] = mod_q(a_ntt[i] * b_ntt[i]);
    }

    ntt(&mut c_ntt, true);

    let mut result = [0i32; N];
    for i in 0..N {
        // 역 비틀기.  c_ntt[i] 는 이미 [0,256], PSI_INV_TABLE[i] 도 [0,256].
        result[i] = mod_q(c_ntt[i] * PSI_INV_TABLE[i]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 검증 기준: 순진한 O(N^2) negacyclic 곱.
    fn naive_negacyclic(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
        let mut res = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let k = i + j;
                let p = a[i] as i64 * b[j] as i64;
                if k < N {
                    res[k] += p;
                } else {
                    res[k - N] -= p;
                }
            }
        }
        let mut out = [0i32; N];
        for i in 0..N {
            out[i] = res[i].rem_euclid(Q as i64) as i32;
        }
        out
    }

    fn norm(v: &[i32; N]) -> [i32; N] {
        let mut o = [0i32; N];
        for i in 0..N {
            o[i] = ((v[i] % Q) + Q) % Q;
        }
        o
    }

    #[test]
    fn roots_are_consistent() {
        // psi^N == -1 (mod Q),  omega == psi^2,  omega^N == 1
        let mut p = 1i64;
        for _ in 0..N {
            p = p * PSI as i64 % Q as i64;
        }
        assert_eq!(p, (Q - 1) as i64); // 256 == -1
        assert_eq!((PSI * PSI).rem_euclid(Q), OMEGA);
        assert_eq!((OMEGA * OMEGA_INV).rem_euclid(Q), 1);
        assert_eq!((PSI * PSI_INV).rem_euclid(Q), 1);
        assert_eq!((N as i32 * N_INV).rem_euclid(Q), 1);
    }

    #[test]
    fn convolution_matches_naive_random() {
        // 결정적 LCG 로 다수의 랜덤 케이스 검증.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as i32
        };

        for _ in 0..1000 {
            let mut a = [0i32; N];
            let mut b = [0i32; N];
            for i in 0..N {
                a[i] = next().rem_euclid(Q);
                b[i] = next().rem_euclid(Q);
            }
            let expect = naive_negacyclic(&a, &b);
            let got = norm(&negacyclic_convolution(&a, &b));
            assert_eq!(got, expect);
        }
    }

    #[test]
    fn forward_then_inverse_is_identity() {
        let mut state: u64 = 0xdead_beef_cafe_babe;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as i32
        };
        for _ in 0..200 {
            let mut a = [0i32; N];
            for i in 0..N {
                a[i] = next().rem_euclid(Q);
            }
            let original = a;
            ntt(&mut a, false);
            ntt(&mut a, true);
            assert_eq!(norm(&a), norm(&original));
        }
    }
}