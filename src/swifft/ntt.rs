// src/swifft/ntt.rs

// 상위 모듈(mod.rs)에 정의된 공통 구조체와 상수를 가져옵니다.
use super::{SwifftPoly, M};

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
        let rev = reverse_bits(i, LOG_N as u32);
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
        let w_len = mod_exp(root, N / len);

        for i in (0..N).step_by(len) {
            let mut w = 1;
            for j in 0..half {
                let u = a[i + j];
                let v = mod_q(a[i + j + half] * w); 
                
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

    for i in 0..N {
        a_ntt[i] = mod_q(a[i] * mod_exp(PSI, i));
        b_ntt[i] = mod_q(b[i] * mod_exp(PSI, i));
    }

    ntt(&mut a_ntt, false);
    ntt(&mut b_ntt, false);

    let mut c_ntt = [0; N];
    for i in 0..N {
        c_ntt[i] = mod_q(a_ntt[i] * b_ntt[i]);
    }

    ntt(&mut c_ntt, true);

    let mut result = [0; N];
    for i in 0..N {
        result[i] = mod_q(c_ntt[i] * mod_exp(PSI_INV, i)); 
    }

    result
}

/// SWIFFT 해시 인스턴스 구조체 (NTT 기반 스칼라 버전)
#[derive(Clone, Debug)]
pub struct SwifftHasherNTT {
    pub a_keys_ntt: [SwifftPoly; M],
}

impl SwifftHasherNTT {
    /// 새로운 SWIFFT 해시 인스턴스 생성 및 키 전처리
    pub fn new(raw_keys: &[[i32; N]; M]) -> Self {
        let mut a_keys_ntt = [SwifftPoly::zero(); M];

        for i in 0..M {
            let mut key_ntt = [0; N];
            
            for j in 0..N {
                let psi_power = mod_exp(PSI, j);
                key_ntt[j] = mod_q(raw_keys[i][j] * psi_power);
            }
            
            ntt(&mut key_ntt, false);
            a_keys_ntt[i] = SwifftPoly::new(key_ntt);
        }

        Self { a_keys_ntt }
    }

    /// NTT를 사용한 스칼라 방식의 해시 함수
    pub fn hash(&self, input: &[u8]) -> SwifftPoly {
        assert_eq!(input.len(), 256, "SWIFFT input must be 256 bytes");

        let mut result_ntt = [0i32; N];

        for i in 0..M {
            let mut x_poly = [0i32; N];
            let chunk = &input[i * 16..(i + 1) * 16];
            
            for j in 0..16 {
                let byte = chunk[j];
                for b in 0..4 {
                    x_poly[j * 4 + b] = ((byte >> (b * 2)) & 0x03) as i32;
                }
            }

            ntt(&mut x_poly, false);

            for k in 0..N {
                let term = mod_q(self.a_keys_ntt[i].coeffs[k] * x_poly[k]);
                result_ntt[k] = mod_q(result_ntt[k] + term);
            }
        }

        ntt(&mut result_ntt, true);

        let mut final_result = [0i32; N];
        for j in 0..N {
            let psi_inv_power = mod_exp(PSI_INV, j);
            final_result[j] = mod_q(result_ntt[j] * psi_inv_power);
        }

        SwifftPoly::new(final_result)
    }
}