// src/swifft/ntt.rs

pub const Q: i32 = 257;
pub const N: usize = 64;
pub const LOG_N: usize = 6;

// 사전에 계산된 최적화 상수들
pub const PSI: i32 = 9;
pub const PSI_INV: i32 = 200; // 정정된 역원
pub const OMEGA: i32 = 81;
pub const OMEGA_INV: i32 = 165; 
pub const N_INV: i32 = 253;

/// 안전한 모듈러 연산 헬퍼 (Rust의 % 연산자는 음수 결과를 반환할 수 있으므로 보정)
#[inline(always)]
pub fn mod_q(x: i32) -> i32 {
    let mut res = x % Q;
    if res < 0 {
        res += Q;
    }
    res
}

/// 거듭제곱(Modular Exponentiation) 연산
pub fn mod_exp(mut base: i32, mut exp: usize) -> i32 {
    let mut res = 1;
    base = mod_q(base);
    while exp > 0 {
        if exp % 2 == 1 {
            res = mod_q(res * base);
        }
        base = mod_q(base * base);
        exp /= 2;
    }
    res
}

/// 비트 반전 (Bit-reversal) 로직
/// 인덱스 0~63의 이진수 비트 배열을 뒤집습니다. (예: 000001 -> 100000)
fn reverse_bits(n: usize, bits: u32) -> usize {
    // usize의 전체 비트를 뒤집은 뒤, 우리가 필요한 비트 수만큼만 오른쪽으로 시프트
    n.reverse_bits() >> (usize::BITS - bits)
}
/// Cooley-Tukey 기반 64-point NTT 및 Inverse NTT 알고리즘
pub fn ntt(a: &mut [i32; N], inverse: bool) {
    // 1. Bit-reversal Permutation (입력 재배치)
    for i in 0..N {
        let rev = reverse_bits(i, LOG_N);
        if i < rev {
            a.swap(i, rev);
        }
    }

    // 2. Butterfly 연산을 위한 Root 설정 (방향에 따라 OMEGA 또는 OMEGA_INV 선택)
    let root = if inverse { OMEGA_INV } else { OMEGA };

    // 3. Cooley-Tukey Butterfly Loop
    let mut len = 2;
    while len <= N {
        let half = len / 2;
        // 현재 부분 문제의 크기에 맞는 w_len 도출 (w_len = root^(N/len))
        let w_len = mod_exp(root, N / len);

        for i in (0..N).step_by(len) {
            let mut w = 1;
            for j in 0..half {
                let u = a[i + j];
                // 회전 인자(Twiddle factor)를 곱한 값
                let v = mod_q(a[i + j + half] * w); 
                
                // 나비 연산 (교차 더하기/빼기)
                a[i + j] = mod_q(u + v);
                a[i + j + half] = mod_q(u - v);
                
                w = mod_q(w * w_len);
            }
        }
        len *= 2;
    }

    // 4. Inverse NTT일 경우 최종적으로 N^{-1} 곱하기
    if inverse {
        for i in 0..N {
            a[i] = mod_q(a[i] * N_INV);
        }
    }
}

/// 최종 Negacyclic Convolution 실행 (Weighting -> NTT -> Mul -> INTT -> Unweighting)
pub fn negacyclic_convolution(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut a_ntt = [0; N];
    let mut b_ntt = [0; N];

    // [Step 1] 전처리(Weighting): a'_i = a_i * \psi^i
    for i in 0..N {
        a_ntt[i] = mod_q(a[i] * mod_exp(PSI, i));
        b_ntt[i] = mod_q(b[i] * mod_exp(PSI, i));
    }

    // [Step 2] Standard NTT 수행
    ntt(&mut a_ntt, false);
    ntt(&mut b_ntt, false);

    // [Step 3] Point-wise Multiplication (인덱스별 스칼라 곱)
    let mut c_ntt = [0; N];
    for i in 0..N {
        c_ntt[i] = mod_q(a_ntt[i] * b_ntt[i]);
    }

    // [Step 4] Inverse NTT 수행 (결과는 다시 시간 영역으로 복원됨)
    ntt(&mut c_ntt, true);

    // [Step 5] 후처리(Unweighting): c_i = c'_i * \psi^{-i}
    let mut result = [0; N];
    for i in 0..N {
        result[i] = mod_q(c_ntt[i] * mod_exp(PSI_INV, i)); 
        // 64^{-1} 곱셈은 INTT 내부에서 이미 처리되었으므로 PSI_INV만 곱함
    }

    result
}