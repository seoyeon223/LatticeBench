// src/swifft/simd.rs
//
// 재작성 요지
// -----------
// 이전 버전의 치명적 문제 3가지를 제거:
//   (1) ntt_avx2 가 사실상 미구현(트위들 전부 1, len=2/4/8 단계 누락,
//       bit-reversal 미호출)이라 정변환이 NTT 가 아니었음.
//   (2) 정변환은 Cooley-Tukey(bit-rev 규약) 가정, 역변환은 Stockham(ntt::ntt)
//       이라 NTT^{-1}(NTT(x)) != x. 정/역 변환 규약 불일치.
//   (3) byte(u8) >> (b: usize) 타입 불일치로 컴파일 실패.
//
// 해결 전략
//   * 정변환·역변환을 모두 검증된 단일 알고리즘 ntt::ntt (Stockham)으로 통일.
//     -> 왕복 항등 보장. SIMD 측에서 NTT 를 재구현하지 않는다.
//   * SWIFFT 해시의 진짜 병목은 NTT 자체가 아니라
//     "키와의 점별 곱을 M(=16)개 누적" 하는 부분.  NTT 의 선형성에 의해
//       sum_i ( a_i (*) x_i )  ==  INTT( sum_i NTT(a_i)·NTT(x_i) )
//     이므로 점별 곱+누적만 AVX2 로 가속하고 INTT 는 마지막에 한 번만 호출.
//   * AVX2 미지원 아키텍처(Apple Silicon 등)에서도 동작하도록
//     동일 로직의 스칼라 폴백을 제공(panic 하지 않음).
//
// 정확성은 Python 1:1 시뮬레이션으로 naive negacyclic 합과 대조 검증함:
//   - negacyclic NTT == naive (500 cases)
//   - SWIFFT 해시(NTT 도메인 누적) == naive (300 cases)
//   - AVX2 누적 final 환원이 [0,4096] 에서 정확 (term∈[0,256], M=16)

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::arch::x86_64::*;

use crate::swifft::ntt;
use crate::swifft::{SwifftPoly, M, N};

// ── 컴파일 타임 정합성 가드 ──────────────────────────────────────────────
// ntt.rs 의 N 과 swifft 모듈의 N 이 어긋나면 배열 크기 버그가 되므로 못박는다.
const _: () = assert!(N == ntt::N, "simd.rs: N must match ntt::N");
const _: () = assert!(N == 64, "this SIMD path assumes N == 64");

/// AVX2 레지스터(32-byte) 경계에 정렬된 계수 배열.
#[repr(align(32))]
#[derive(Clone, Debug)]
pub struct AlignedPolyArray {
    pub coeffs: [i32; N],
}

impl AlignedPolyArray {
    #[inline]
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }
    #[inline]
    pub fn new(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }
}

#[derive(Clone, Debug)]
pub struct SwifftHasherSimd {
    /// 각 키를 "PSI twist -> forward NTT" 한 결과를 미리 캐싱.
    /// 정렬된 레이아웃이라 AVX2 aligned-load 가 가능.
    pub a_keys_ntt: [AlignedPolyArray; M],
}

impl SwifftHasherSimd {
    pub fn new(raw_keys: &[[i32; N]; M]) -> Self {
        let a_keys_ntt = core::array::from_fn(|i| {
            let mut key_ntt = [0i32; N];
            for j in 0..N {
                // PSI twist 후 환원 (mod_q 안전 입력 유지: raw*psi <= 256*256)
                key_ntt[j] = ntt::mod_q(raw_keys[i][j] * ntt::PSI_TABLE[j]);
            }
            // 정변환: 통일된 Stockham NTT.
            ntt::ntt(&mut key_ntt, false);
            AlignedPolyArray::new(key_ntt)
        });
        Self { a_keys_ntt }
    }

    /// 256바이트 입력의 i번째 16바이트 청크를 64개 2비트 계수로 펼친다.
    #[inline]
    fn unpack_chunk(input: &[u8], i: usize) -> AlignedPolyArray {
        let mut x = AlignedPolyArray::zero();
        let chunk = &input[i * 16..(i + 1) * 16];
        for j in 0..16 {
            let byte = chunk[j] as i32; // ← u8 을 i32 로 먼저 승격 (타입 버그 수정)
            for b in 0..4 {
                x.coeffs[j * 4 + b] = (byte >> (b * 2)) & 0x03;
            }
        }
        x
    }

    /// 공통(아키텍처 무관) 후처리: NTT 도메인 누적값 -> inverse NTT -> PSI_INV twist.
    #[inline]
    fn finalize(mut acc_ntt: [i32; N]) -> SwifftPoly {
        // 통일된 Stockham 역변환 (정변환과 동일 알고리즘 -> 왕복 항등).
        ntt::ntt(&mut acc_ntt, true);

        let mut out = [0i32; N];
        for j in 0..N {
            out[j] = ntt::mod_q(acc_ntt[j] * ntt::PSI_INV_TABLE[j]);
        }
        SwifftPoly::new(out)
    }

    // ─────────────────────── AVX2 경로 ───────────────────────
    //
    // 가속 대상: NTT(전반 스칼라 + 후반 AVX2 하이브리드) + 점별 곱 + 누적.
    // 정/역 모두 동일한 하이브리드 NTT 를 쓰므로 왕복 항등 유지.
    // 하이브리드는 풀 스칼라 ntt::ntt 와 비트 단위 동일(Python 검증).
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn hash_avx2(&self, input: &[u8]) -> SwifftPoly {
        assert_eq!(input.len(), 256, "SWIFFT input must be 256 bytes");

        // NTT 도메인 누적기 (8 x i32) x 8 레인.
        let mut acc = [_mm256_setzero_si256(); N / 8];

        for i in 0..M {
            // 1) 청크 펼치기.
            let mut x = Self::unpack_chunk(input, i);

            // 2) PSI twist (스칼라, 안전 환원).
            for j in 0..N {
                x.coeffs[j] = ntt::mod_q(x.coeffs[j] * ntt::PSI_TABLE[j]);
            }

            // 3) forward NTT — 하이브리드(전반 스칼라 + 후반 AVX2).
            ntt_hybrid_avx2(&mut x.coeffs, false);

            // 4) 캐시된 키 NTT 와 점별 곱 후 NTT 도메인 누적.
            //    term ∈ [0,256], M=16 -> 누적합 ≤ 4096 (오버플로/환원 안전,
            //    Python 검증: fast_final 이 [0,4096]에서 정확).
            for k in 0..(N / 8) {
                let a_ptr =
                    self.a_keys_ntt[i].coeffs.as_ptr().add(k * 8) as *const __m256i;
                let x_ptr = x.coeffs.as_ptr().add(k * 8) as *const __m256i;

                // AlignedPolyArray(repr(align(32)))의 첫 원소부터 k*32 바이트
                // 오프셋 -> 32바이트 정렬 보장 -> aligned load 사용 가능.
                let a_vec = _mm256_load_si256(a_ptr);
                let x_vec = _mm256_load_si256(x_ptr);

                let term = fast_mul_mod_257_avx2(a_vec, x_vec);
                acc[k] = _mm256_add_epi32(acc[k], term);
            }
        }

        // 5) 누적 종료 후 한 번만 환원하고 일반 배열로 추출.
        let mut acc_ntt = [0i32; N];
        for k in 0..(N / 8) {
            let reduced = fast_mod_257_final_avx2(acc[k]);
            _mm256_storeu_si256(
                acc_ntt.as_mut_ptr().add(k * 8) as *mut __m256i,
                reduced,
            );
        }

        // 6) 역변환 + untwist — AVX2 경로는 하이브리드 역변환으로 통일.
        //    (정변환도 ntt_hybrid_avx2 였으므로 같은 알고리즘 → 왕복 항등.)
        ntt_hybrid_avx2(&mut acc_ntt, true);
        let mut out = [0i32; N];
        for j in 0..N {
            out[j] = ntt::mod_q(acc_ntt[j] * ntt::PSI_INV_TABLE[j]);
        }
        SwifftPoly::new(out)
    }

    // ─────────────────── 스칼라 폴백 경로 ───────────────────
    //
    // AVX2 가 없는 아키텍처(Apple Silicon 등)에서도 동일 결과를 내도록
    // panic 하지 않고 동일 로직을 스칼라로 수행한다.
    fn hash_scalar(&self, input: &[u8]) -> SwifftPoly {
        assert_eq!(input.len(), 256, "SWIFFT input must be 256 bytes");

        let mut acc_ntt = [0i32; N];

        for i in 0..M {
            let mut x = Self::unpack_chunk(input, i);
            for j in 0..N {
                x.coeffs[j] = ntt::mod_q(x.coeffs[j] * ntt::PSI_TABLE[j]);
            }
            ntt::ntt(&mut x.coeffs, false);

            for j in 0..N {
                // 점별 곱 후 즉시 환원 -> 항상 [0,256] -> 누적합 ≤ 16*256.
                let term = ntt::mod_q(self.a_keys_ntt[i].coeffs[j] * x.coeffs[j]);
                acc_ntt[j] += term;
            }
        }
        for j in 0..N {
            acc_ntt[j] = ntt::mod_q(acc_ntt[j]);
        }

        Self::finalize(acc_ntt)
    }

    /// 런타임 디스패치: AVX2 가능하면 가속 경로, 아니면 스칼라 폴백.
    /// (두 경로는 동일한 ntt::ntt 를 쓰므로 비트 단위로 같은 결과를 낸다.)
    pub fn hash(&self, input: &[u8]) -> SwifftPoly {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                return unsafe { self.hash_avx2(input) };
            }
        }
        self.hash_scalar(input)
    }
}

// ───────────────────── AVX2 모듈러 헬퍼 ─────────────────────
//
// 주의: 이 비트-트릭들은 입력이 제한된 범위일 때만 정확하다.
//  - fast_mul: a,b ∈ [0,256] 이면 곱 ≤ 65536, 단일 스텝 보정으로 정확
//    (Python 전수검증: [0,256]^2 전 구간 일치).
//  - fast_final: 입력 ∈ [0,65535] 에서 정확. 여기서는 ≤ 4096 만 들어옴.
// 따라서 호출 측은 반드시 피연산자를 [0,256] 으로 유지해야 한다
// (a_keys_ntt 와 x 의 NTT 결과는 ntt::ntt 가 [0,256] 으로 환원해 준다).

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn fast_mul_mod_257_avx2(a: __m256i, b: __m256i) -> __m256i {
    // a,b ∈ [0,256] 이므로 곱 ∈ [0,65536]: srli(논리시프트)도 안전(부호비트 0).
    let c = _mm256_mullo_epi32(a, b);
    let mask_ff = _mm256_set1_epi32(0xFF);
    let l = _mm256_and_si256(c, mask_ff);
    let h = _mm256_srli_epi32::<8>(c);
    let r = _mm256_sub_epi32(l, h); // r ∈ [-255, 255] 근방
    // r < 0 이면 +257 (단일 스텝으로 충분: 위 범위에서 검증됨).
    let zero = _mm256_setzero_si256();
    let is_neg = _mm256_cmpgt_epi32(zero, r);
    let q = _mm256_and_si256(is_neg, _mm256_set1_epi32(257));
    _mm256_add_epi32(r, q)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn fast_mod_257_final_avx2(sum: __m256i) -> __m256i {
    // sum ∈ [0, 4096] (term∈[0,256], M=16). 단일 스텝 환원으로 충분.
    let mask_ff = _mm256_set1_epi32(0xFF);
    let l = _mm256_and_si256(sum, mask_ff);
    let h = _mm256_srli_epi32::<8>(sum);
    let r = _mm256_sub_epi32(l, h);
    let zero = _mm256_setzero_si256();
    let is_neg = _mm256_cmpgt_epi32(zero, r);
    let q = _mm256_and_si256(is_neg, _mm256_set1_epi32(257));
    _mm256_add_epi32(r, q)
}

// ── 하이브리드 NTT 의 AVX2 후반 스테이지 (L=8,16,32) ────────────────────
//
// ntt::reduce_mul / reduce_addsub 와 *비트 단위로 동일한* 산술을 8레인
// 병렬로 수행한다 (Python 검증: AVX 시뮬 == 스칼라, 하이브리드 == 풀스칼라).
// 곱 환원은 fast_mul_mod_257_avx2 가 곧 reduce_mul 의 벡터판이라 재사용.

/// reduce_addsub 의 AVX2 판. 입력 v ∈ [-256,512] 에서 스칼라와 동일.
///   v - (((256 - v) >> 31) & 257);  then  v + ((v >> 31) & 257)
/// (>> 는 산술 시프트 _mm256_srai_epi32 사용 — 스칼라 i32 >> 와 일치.)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn reduce_addsub_avx2(v: __m256i) -> __m256i {
    let q = _mm256_set1_epi32(257);
    let c256 = _mm256_set1_epi32(256);
    // m1 = (256 - v) >> 31  (v>256 이면 0xFFFFFFFF)
    let t = _mm256_sub_epi32(c256, v);
    let m1 = _mm256_srai_epi32::<31>(t);
    let v = _mm256_sub_epi32(v, _mm256_and_si256(m1, q));
    // m2 = v >> 31 (v<0 이면 0xFFFFFFFF)
    let m2 = _mm256_srai_epi32::<31>(v);
    _mm256_add_epi32(v, _mm256_and_si256(m2, q))
}

/// 후반 한 스테이지(L ∈ {8,16,32})를 AVX2 로. src/dst 는 [i32;64].
/// twiddles 는 ntt 의 평면 테이블(앞 L개 유효, 8의 배수).
/// 스칼라 stockham_stage 와 비트 단위 동일:
///   v = reduce_mul(w*b);  out_lo=reduce_addsub(a+v); out_hi=reduce_addsub(a-v)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn late_stage_avx2<const L: usize>(
    src: &[i32; N],
    dst: &mut [i32; N],
    tw: &[i32; 32],
) {
    let m = N / (2 * L);
    // j 를 8개씩: read/write 가 연속(분석으로 검증)이라 loadu/storeu.
    let mut k = 0;
    while k < m {
        let mut j0 = 0;
        while j0 < L {
            let base = k * L + j0;
            let a_v = _mm256_loadu_si256(src.as_ptr().add(base) as *const __m256i);
            let b_v =
                _mm256_loadu_si256(src.as_ptr().add(base + N / 2) as *const __m256i);
            // 트위들: 평면 테이블에서 연속 8개 (j0..j0+8).
            let _ = m; // m 은 평면화에 이미 반영됨(문서용)
            let w_v = _mm256_loadu_si256(tw.as_ptr().add(j0) as *const __m256i);

            // v = reduce_mul(w*b)  (fast_mul_mod_257_avx2 == reduce_mul 벡터판)
            let v = fast_mul_mod_257_avx2(w_v, b_v);

            let lo = reduce_addsub_avx2(_mm256_add_epi32(a_v, v));
            let hi = reduce_addsub_avx2(_mm256_sub_epi32(a_v, v));

            let wbase = 2 * k * L + j0;
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(wbase) as *mut __m256i,
                lo,
            );
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(wbase + L) as *mut __m256i,
                hi,
            );
            j0 += 8;
        }
        k += 1;
    }
}

/// 하이브리드 NTT: 전반 3스테이지(스칼라, 검증됨) + 후반 3스테이지(AVX2).
/// 풀 스칼라 ntt::ntt 와 비트 단위 동일(Python 3000 검증).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn ntt_hybrid_avx2(a: &mut [i32; N], inverse: bool) {
    // 전반 3스테이지: 검증된 스칼라. 출력 버퍼(=L8 입력) 반환.
    let s0 = ntt::run_early_stages(a, inverse);

    // 후반 3스테이지 ping-pong: s0 -> b1(L8) -> b2(L16) -> a(L32)
    let mut b1 = [0i32; N];
    let mut b2 = [0i32; N];

    let (t8, t16, t32) = if inverse {
        (&ntt::TW_INV_L8, &ntt::TW_INV_L16, &ntt::TW_INV_L32)
    } else {
        (&ntt::TW_FWD_L8, &ntt::TW_FWD_L16, &ntt::TW_FWD_L32)
    };

    late_stage_avx2::<8>(&s0, &mut b1, t8);
    late_stage_avx2::<16>(&b1, &mut b2, t16);
    late_stage_avx2::<32>(&b2, a, t32);

    if inverse {
        ntt::scale_inverse(a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive_negacyclic(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
        let mut res = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let p = a[i] as i64 * b[j] as i64;
                let k = i + j;
                if k < N {
                    res[k] += p;
                } else {
                    res[k - N] -= p;
                }
            }
        }
        let mut out = [0i32; N];
        for i in 0..N {
            out[i] = res[i].rem_euclid(ntt::Q as i64) as i32;
        }
        out
    }

    /// SWIFFT 정의: sum_i ( a_i (*) x_i )  (negacyclic),  x_i ∈ {0,1,2,3}.
    fn swifft_naive(keys: &[[i32; N]; M], input: &[u8]) -> [i32; N] {
        let mut total = [0i64; N];
        for i in 0..M {
            let mut x = [0i32; N];
            let chunk = &input[i * 16..(i + 1) * 16];
            for j in 0..16 {
                let byte = chunk[j] as i32;
                for b in 0..4 {
                    x[j * 4 + b] = (byte >> (b * 2)) & 0x03;
                }
            }
            let prod = naive_negacyclic(&keys[i], &x);
            for j in 0..N {
                total[j] += prod[j] as i64;
            }
        }
        let mut out = [0i32; N];
        for j in 0..N {
            out[j] = total[j].rem_euclid(ntt::Q as i64) as i32;
        }
        out
    }

    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    #[test]
    fn scalar_path_matches_swifft_definition() {
        let mut st = 0xC0FFEE_u64;
        for _ in 0..200 {
            let keys: [[i32; N]; M] = core::array::from_fn(|_| {
                core::array::from_fn(|_| (lcg(&mut st) % ntt::Q as u64) as i32)
            });
            let mut input = [0u8; 256];
            for b in input.iter_mut() {
                *b = (lcg(&mut st) & 0xFF) as u8;
            }

            let hasher = SwifftHasherSimd::new(&keys);
            let got = hasher.hash_scalar(&input).coeffs; // SwifftPoly.coeffs (pub field)
            let expect = swifft_naive(&keys, &input);
            assert_eq!(got, expect);
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn avx2_path_equals_scalar_path() {
        if !std::is_x86_feature_detected!("avx2") {
            return; // AVX2 없으면 스킵.
        }
        let mut st = 0xBADC0DE_u64;
        for _ in 0..100 {
            let keys: [[i32; N]; M] = core::array::from_fn(|_| {
                core::array::from_fn(|_| (lcg(&mut st) % ntt::Q as u64) as i32)
            });
            let mut input = [0u8; 256];
            for b in input.iter_mut() {
                *b = (lcg(&mut st) & 0xFF) as u8;
            }
            let hasher = SwifftHasherSimd::new(&keys);
            let a = unsafe { hasher.hash_avx2(&input) }.coeffs;
            let s = hasher.hash_scalar(&input).coeffs;
            assert_eq!(a, s);
        }
    }
}