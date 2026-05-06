// src/swifft/mod.rs

pub mod ntt; // 하위 모듈인 ntt.rs를 공개적으로 포함

/// SWIFFT 알고리즘 규격 상수
pub const M: usize = 16;   // 입력 블록을 나누는 개수 (사용되는 다항식의 수)
pub const N: usize = 64;   // 각 다항식의 차수 (상수항 포함 64개의 계수)
pub const Q: i32 = 257;    // 모듈러 값 (q)

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

/// SWIFFT 해시 인스턴스 구조체
/// 보안성 및 시스템 메모리 효율성을 고려하여 설계되었습니다.
#[derive(Clone, Debug)]
pub struct SwifftHasher {
    /// 해시 함수의 '키(Key)' 역할을 하는 M개의 랜덤 다항식.
    /// [최적화 핵심] 매번 해시 연산을 수행할 때마다 키를 NTT 변환하는 것은 심각한 성능 저하를 초래합니다.
    /// 따라서 객체 생성 시점에 전처리(Weighting) 및 NTT 변환을 미리 수행하여 캐싱(Caching)해 둡니다.
    pub a_keys_ntt: [SwifftPoly; M],
}

impl SwifftHasher {
    /// 새로운 SWIFFT 해시 인스턴스 생성 및 키 전처리
    /// raw_keys: 난수 발생기로 생성된 M개의 N차 다항식 배열
    pub fn new(raw_keys: &[[i32; N]; M]) -> Self {
        let mut a_keys_ntt = [SwifftPoly::zero(); M];

        for i in 0..M {
            let mut key_ntt = [0; N];
            
            // 1. Pre-multiplication (Weighting): a'_j = a_j * \psi^j (mod Q)
            for j in 0..N {
                let psi_power = ntt::mod_exp(ntt::PSI, j);
                key_ntt[j] = ntt::mod_q(raw_keys[i][j] * psi_power);
            }
            
            // 2. Standard NTT 수행 (시간 영역 -> 주파수 영역 변환)
            ntt::ntt(&mut key_ntt, false);
            
            // 3. 변환이 완료된 결과를 구조체에 저장
            a_keys_ntt[i] = SwifftPoly::new(key_ntt);
        }

        Self { a_keys_ntt }
    }

    /// (향후 구현될 부분) 입력된 바이트 배열을 해싱하는 메인 함수
    /// pub fn hash(&self, input: &[u8]) -> [u8; 32] { ... }
}