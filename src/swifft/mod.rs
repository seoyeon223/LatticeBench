// src/swifft/mod.rs
 
pub mod ntt; // 하위 모듈인 ntt.rs를 공개적으로 포함
pub mod naive; // 하위 모듈인 naive.rs를 공개적으로 포함
pub mod simd; // 하위 모듈인 simd.rs를 공개적으로 포함
 
/// SWIFFT 알고리즘 규격 상수
pub const M: usize = 16; // 입력 블록을 나누는 개수 (사용되는 다항식의 수)
pub const N: usize = 64; // 각 다항식의 차수 (상수항 포함 64개의 계수)
pub const Q: i32 = 257; // 모듈러 값 (q)
 
/// 다항식을 표현하는 구조체 (Z_257[X] / (X^64 + 1) 환의 원소)
#[derive(Clone, Copy, Debug)]
pub struct SwifftPoly {
    pub coeffs: [i32; N],
}
 
impl SwifftPoly {
    /// 모든 계수가 0인 다항식 생성
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }
 
    /// 계수 배열로부터 다항식 인스턴스 생성
    pub fn new(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }
}
 
/// SWIFFT 해시 인스턴스 구조체 (NTT 기반 스칼라 버전)
#[derive(Clone, Debug)]
pub struct SwifftHasherNTT {
    /// 해시 함수의 '키(Key)' 역할을 하는 M개의 랜덤 다항식.
    /// 각 키는 "PSI twist -> forward NTT" 한 상태로 캐싱된다.
    pub a_keys_ntt: [SwifftPoly; M],
 
    /// Unweighting 용 psi^{-1} 거듭제곱 캐시.
    pub psi_inv_powers: [i32; N],
}
 
impl SwifftHasherNTT {
    /// 새로운 SWIFFT 해시 인스턴스 생성 및 키 전처리
    pub fn new(raw_keys: &[[i32; N]; M]) -> Self {
        let mut a_keys_ntt = [SwifftPoly::zero(); M];
        let mut psi_inv_powers = [0i32; N];
 
        // 1. 키 다항식 전처리 (PSI twist & forward NTT)
        for i in 0..M {
            let mut key_ntt = [0i32; N];
            for j in 0..N {
                // raw*psi <= 256*256 -> mod_q 안전 입력.
                key_ntt[j] = ntt::mod_q(raw_keys[i][j] * ntt::PSI_TABLE[j]);
            }
            ntt::ntt(&mut key_ntt, false);
            a_keys_ntt[i] = SwifftPoly::new(key_ntt);
        }
 
        // 2. Unweighting 거듭제곱 캐시 채우기.
        //    [버그 수정] 이전 코드는 지역변수에만 대입하고 버려서
        //    psi_inv_powers 가 전부 0 으로 남아 있었다(죽은 필드).
        for j in 0..N {
            psi_inv_powers[j] = ntt::PSI_INV_TABLE[j];
        }
 
        Self {
            a_keys_ntt,
            psi_inv_powers,
        }
    }
 
    /// NTT를 사용한 스칼라 방식의 해시 함수 (SIMD 미사용 버전).
    ///
    /// 정의: out = sum_i ( a_i (*) x_i )  (negacyclic, x^N + 1).
    /// NTT 선형성에 의해
    ///   out = INTT( sum_i NTT(a_i) · NTT(x_i) )  를 PSI_INV 로 untwist.
    /// 정변환·역변환 모두 동일한 ntt::ntt(Stockham)을 쓰므로 왕복 항등.
    pub fn hash(&self, input: &[u8]) -> SwifftPoly {
        assert_eq!(input.len(), 256, "SWIFFT input must be 256 bytes");
 
        let mut result_ntt = [0i32; N];
        let mut x_poly = [0i32; N];
 
        for i in 0..M {
            let chunk = &input[i * 16..(i + 1) * 16];
 
            // 1. 바이트 -> 2비트 계수 4개씩 펼치기.
            //    (i32 로 먼저 승격해야 u8 >> usize 타입 불일치를 피함)
            for j in 0..16 {
                let byte = chunk[j] as i32;
                for b in 0..4 {
                    x_poly[j * 4 + b] = (byte >> (b * 2)) & 0x03;
                }
            }
 
            // 2. PSI twist (mod_q 안전 입력 유지) — 키와 동일 전처리.
            for j in 0..N {
                x_poly[j] = ntt::mod_q(x_poly[j] * ntt::PSI_TABLE[j]);
            }
 
            // 3. 입력 다항식 forward NTT.
            ntt::ntt(&mut x_poly, false);
 
            // 4. 점별 곱 + NTT 도메인 누적.
            for k in 0..N {
                let term = ntt::mod_q(self.a_keys_ntt[i].coeffs[k] * x_poly[k]);
                result_ntt[k] = ntt::mod_q(result_ntt[k] + term);
            }
        }
 
        // 5. 역변환 (INTT) — 정변환과 동일 알고리즘.
        ntt::ntt(&mut result_ntt, true);
 
        // 6. Unweighting (PSI_INV untwist).
        let mut final_result = [0i32; N];
        for j in 0..N {
            final_result[j] = ntt::mod_q(result_ntt[j] * self.psi_inv_powers[j]);
        }
 
        // [버그 수정] 이전 코드는 final_result 를 계산만 하고
        //            untwist 안 된 result_ntt 를 반환했다. 올바른 값을 반환한다.
        SwifftPoly::new(final_result)
    }
}
 
#[cfg(test)]
mod tests {
    use super::*;
 
    /// 기준 정답: SWIFFT 정의 그대로 (negacyclic 곱의 M개 합).
    fn swifft_naive(keys: &[[i32; N]; M], input: &[u8]) -> [i32; N] {
        let mut total = [0i64; N];
        for i in 0..M {
            // 청크 -> 계수
            let mut x = [0i32; N];
            let chunk = &input[i * 16..(i + 1) * 16];
            for j in 0..16 {
                let byte = chunk[j] as i32;
                for b in 0..4 {
                    x[j * 4 + b] = (byte >> (b * 2)) & 0x03;
                }
            }
            // negacyclic 곱 (x^N + 1)
            let mut prod = [0i64; N];
            for p in 0..N {
                for r in 0..N {
                    let v = keys[i][p] as i64 * x[r] as i64;
                    let s = p + r;
                    if s < N {
                        prod[s] += v;
                    } else {
                        prod[s - N] -= v;
                    }
                }
            }
            for j in 0..N {
                total[j] += prod[j];
            }
        }
        let mut out = [0i32; N];
        for j in 0..N {
            out[j] = total[j].rem_euclid(Q as i64) as i32;
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
    fn psi_inv_cache_is_populated() {
        let keys: [[i32; N]; M] = core::array::from_fn(|_| [1i32; N]);
        let h = SwifftHasherNTT::new(&keys);
        // 캐시가 실제로 PSI_INV_TABLE 로 채워졌는지 (이전엔 전부 0이었음).
        for j in 0..N {
            assert_eq!(h.psi_inv_powers[j], ntt::PSI_INV_TABLE[j]);
        }
        assert!(h.psi_inv_powers.iter().any(|&v| v != 0));
    }
 
    #[test]
    fn ntt_hash_matches_swifft_definition() {
        let mut st = 0xABCDEF_u64;
        for _ in 0..200 {
            let keys: [[i32; N]; M] = core::array::from_fn(|_| {
                core::array::from_fn(|_| (lcg(&mut st) % Q as u64) as i32)
            });
            let mut input = [0u8; 256];
            for b in input.iter_mut() {
                *b = (lcg(&mut st) & 0xFF) as u8;
            }
            let got = SwifftHasherNTT::new(&keys).hash(&input).coeffs;
            let expect = swifft_naive(&keys, &input);
            assert_eq!(got, expect);
        }
    }
 
    /// NTT 스칼라 경로와 SIMD 공개 API(hash: 런타임 디스패치)가
    /// 동일 결과인지 교차검증. (AVX2 vs 스칼라폴백 단독 비교는
    /// simd.rs 자체 테스트 avx2_path_equals_scalar_path 가 담당.)
    #[test]
    fn ntt_and_simd_paths_agree() {
        use crate::swifft::simd::SwifftHasherSimd;
        let mut st = 0x13579B_u64;
        for _ in 0..100 {
            let keys: [[i32; N]; M] = core::array::from_fn(|_| {
                core::array::from_fn(|_| (lcg(&mut st) % Q as u64) as i32)
            });
            let mut input = [0u8; 256];
            for b in input.iter_mut() {
                *b = (lcg(&mut st) & 0xFF) as u8;
            }
 
            let ntt_path = SwifftHasherNTT::new(&keys).hash(&input).coeffs;
            let simd_path = SwifftHasherSimd::new(&keys).hash(&input).coeffs;
            assert_eq!(ntt_path, simd_path, "NTT scalar vs SIMD path mismatch");
        }
    }
}