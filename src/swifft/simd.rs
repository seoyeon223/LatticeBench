// src/swifft/simd.rs

// 🟢 파일 전체를 막지 않고, 필요한 부분(import)에만 x86 제한을 둡니다.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::arch::x86_64::*;

use crate::swifft::ntt;
use crate::swifft::{SwifftPoly, M, N}; // Q는 사용되지 않으면 생략 가능

#[derive(Clone, Debug)]
pub struct SwifftHasherSimd {
    pub a_keys_ntt: [SwifftPoly; M],
}

impl SwifftHasherSimd {
    pub fn new(raw_keys: &[[i32; N]; M]) -> Self {
        let mut a_keys_ntt = [SwifftPoly::zero(); M];
        for i in 0..M {
            let mut key_ntt = [0; N];
            for j in 0..N {
                let psi_power = ntt::mod_exp(ntt::PSI, j);
                key_ntt[j] = ntt::mod_q(raw_keys[i][j] * psi_power);
            }
            ntt::ntt(&mut key_ntt, false);
            a_keys_ntt[i] = SwifftPoly::new(key_ntt);
        }
        Self { a_keys_ntt }
    }

    /// AVX2를 활용하여 256바이트 입력을 초고속으로 해싱합니다.
    /// 🟢 x86 환경에서만 컴파일되도록 제한
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    pub unsafe fn hash_avx2(&self, input: &[u8]) -> SwifftPoly {
        assert_eq!(input.len(), 256, "SWIFFT input must be 256 bytes");

        // 256-bit(8개의 i32) 레지스터로 결과값을 누적할 배열 초기화
        let mut result_simd = [_mm256_setzero_si256(); N / 8];

        for i in 0..M {
            let mut x_poly = [0; N];
            let chunk = &input[i * 16..(i + 1) * 16];
            
            // 바이트 -> 계수 매핑 (비트 추출)
            for j in 0..16 {
                let byte = chunk[j];
                for b in 0..4 {
                    x_poly[j * 4 + b] = ((byte >> (b * 2)) & 0x03) as i32;
                }
            }

            // 입력 다항식 NTT 변환
            ntt::ntt(&mut x_poly, false);

            // 🚀 [초고속 SIMD 구간] 8개씩 묶어서 Pointwise Mul & Accumulate 수행
            for k in 0..(N / 8) {
                // 메모리에서 8개의 계수를 한 번에 레지스터로 로드
                let a_vec = _mm256_loadu_si256(self.a_keys_ntt[i].coeffs.as_ptr().add(k * 8) as *const __m256i);
                let x_vec = _mm256_loadu_si256(x_poly.as_ptr().add(k * 8) as *const __m256i);

                // SIMD 곱셈 및 고속 모듈러 257 축소
                let term = fast_mul_mod_257_avx2(a_vec, x_vec);
                
                // SIMD 덧셈 및 모듈러 축소
                let sum = _mm256_add_epi32(result_simd[k], term);
                result_simd[k] = fast_mod_257_add_avx2(sum);
            }
        }

        // SIMD 레지스터의 결과를 일반 배열로 추출
        let mut result_ntt = [0; N];
        for k in 0..(N / 8) {
            _mm256_storeu_si256(result_ntt.as_mut_ptr().add(k * 8) as *mut __m256i, result_simd[k]);
        }

        // 역변환 (INTT)
        ntt::ntt(&mut result_ntt, true);

        // Unweighting 후처리
        let mut final_result = [0; N];
        for j in 0..N {
            let psi_inv_power = ntt::mod_exp(ntt::PSI_INV, j);
            final_result[j] = ntt::mod_q(result_ntt[j] * psi_inv_power);
        }

        SwifftPoly::new(final_result)
    }

    /// 안전한 외부 인터페이스 래퍼 (어느 아키텍처에서든 호출은 가능하게 만듦)
    pub fn hash(&self, input: &[u8]) -> SwifftPoly {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                return unsafe { self.hash_avx2(input) };
            }
        }
        
        // 🟢 AVX2 미지원 환경(예: ARM Mac)을 위한 Fallback
        // Mac에서는 SIMD가 동작하지 않으므로 에러를 발생시키거나 스칼라(NTT) 버전을 사용해야 합니다.
        panic!("AVX2 is not supported on this architecture (e.g., Apple Silicon). Please use SwifftHasherNTT instead.");
    }
}

/// AVX2 레지스터 기반 초고속 곱셈 및 모듈러 257 연산 (c = a * b mod 257)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn fast_mul_mod_257_avx2(a: __m256i, b: __m256i) -> __m256i {
    let c = _mm256_mullo_epi32(a, b);

    let mask_ff = _mm256_set1_epi32(0xFF);
    let l = _mm256_and_si256(c, mask_ff);

    let h = _mm256_srli_epi32(c, 8);

    let mut r = _mm256_sub_epi32(l, h);

    let zero = _mm256_setzero_si256();
    let is_negative = _mm256_cmpgt_epi32(zero, r); // zero > r => r < 0
    let q_mask = _mm256_and_si256(is_negative, _mm256_set1_epi32(257));
    r = _mm256_add_epi32(r, q_mask);

    r
}

/// AVX2 레지스터 기반 덧셈 보정 연산
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn fast_mod_257_add_avx2(sum: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi32(257);
    let is_geq_q = _mm256_cmpgt_epi32(sum, _mm256_set1_epi32(256)); // sum >= 257
    let subtract_q = _mm256_and_si256(is_geq_q, q_vec);
    _mm256_sub_epi32(sum, subtract_q)
}