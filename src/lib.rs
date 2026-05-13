// lattice-bench/src/lib.rs

/// SWIFFT에서 사용하는 모듈러스 (q = 257)
pub const SWIFFT_MODULUS: u16 = 257;

/// 다항식의 최대 차수 (N = 64)
pub const SWIFFT_DEGREE: usize = 64;

/// SWIFFT 다항식 구조체
/// 64개의 계수를 가지며, 각 계수는 0 ~ 256 사이의 값(u16)을 가집니다.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SwifftPoly {
    pub coeffs: [u16; SWIFFT_DEGREE],
}

impl SwifftPoly {
    /// 모든 계수가 0인 빈 다항식을 생성합니다.
    pub fn new() -> Self {
        SwifftPoly {
            coeffs: [0; SWIFFT_DEGREE],
        }
    }

    /// 계수가 범위를 벗어나지 않도록 모듈러 연산을 수행하며 두 다항식을 더합니다.
    /// (a + b) mod 257
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..SWIFFT_DEGREE {
            // 두 계수를 더한 뒤 257로 나눈 나머지를 저장합니다.
            // u16을 사용하므로 덧셈 시 오버플로우가 발생하지 않습니다.
            result.coeffs[i] = (self.coeffs[i] + other.coeffs[i]) % SWIFFT_MODULUS;
        }
        result
    }
    // lattice-bench/src/lib.rs 파일 내부의 impl SwifftPoly 블록 안에 추가

    /// O(N^2) 시간 복잡도를 가지는 기본 다항식 곱셈
    /// X^64 + 1 모듈러 축소(Negacyclic Convolution)를 포함합니다.
    pub fn mul_naive(&self, other: &Self) -> Self {
        let mut result = Self::new();
        // 곱셈 누적 과정에서 257을 초과하는 값을 안전하게 담기 위해 임시 배열은 u32를 사용
        let mut temp = [0u32; SWIFFT_DEGREE];

        for i in 0..SWIFFT_DEGREE {
            for j in 0..SWIFFT_DEGREE {
                let k = i + j;
                // 계수 곱셈
                let prod = (self.coeffs[i] as u32) * (other.coeffs[j] as u32);
                
                if k < SWIFFT_DEGREE {
                    // 차수가 64 미만이면 그대로 누적
                    temp[k] += prod;
                } else {
                    // 차수가 64 이상이면 X^64 = -1 규칙 적용
                    let reduced_k = k - SWIFFT_DEGREE;
                    
                    // 모듈러 연산에서 빼기(-prod)는 (MODULUS - (prod % MODULUS))를 더하는 것과 동일
                    let mod_prod = prod % (SWIFFT_MODULUS as u32);
                    let neg_prod = (SWIFFT_MODULUS as u32) - mod_prod;
                    
                    temp[reduced_k] += neg_prod;
                }
            }
        }

        // 모든 누적이 끝난 후 최종적으로 257 모듈러 연산을 수행하여 u16으로 변환
        for i in 0..SWIFFT_DEGREE {
            result.coeffs[i] = (temp[i] % (SWIFFT_MODULUS as u32)) as u16;
        }
        
        result
    }
}
// lattice-bench/src/lib.rs 추가

/// SWIFFT에서 사용하는 다항식의 개수 (m = 16)
pub const SWIFFT_M: usize = 16;

/// SWIFFT 해시 인스턴스
/// 시스템 파라미터로 16개의 고정된 무작위 다항식(키)을 가집니다.
pub struct SwifftHasher {
    pub keys: [SwifftPoly; SWIFFT_M],
}

impl SwifftHasher {
    /// 벤치마크를 위해 임의의 키 값을 가진 해시 인스턴스를 생성합니다.
    /// (실제 시스템에서는 암호학적으로 안전한 난수 발생기를 사용해 생성 및 고정해야 합니다.)
    pub fn new() -> Self {
        let mut keys = [SwifftPoly::new(); SWIFFT_M];
        for i in 0..SWIFFT_M {
            for j in 0..SWIFFT_DEGREE {
                // 테스트용 더미 난수 생성 (i * j mod 257)
                keys[i].coeffs[j] = ((i * j) % (SWIFFT_MODULUS as usize)) as u16;
            }
        }
        Self { keys }
    }

    /// 16개의 입력 다항식을 받아 1개의 다항식으로 해싱(압축)합니다.
    pub fn compress(&self, inputs: &[SwifftPoly; SWIFFT_M]) -> SwifftPoly {
        let mut result = SwifftPoly::new();
        
        for i in 0..SWIFFT_M {
            // H = H + (a_i * x_i)
            let term = self.keys[i].mul_naive(&inputs[i]);
            result = result.add(&term);
        }
        
        result
    }
}
// -------------------------------------------------------------
// 작성한 로직이 수학적으로 올바른지 검증하는 유닛 테스트
// -------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_mul_naive() {
        let mut poly1 = SwifftPoly::new();
        let mut poly2 = SwifftPoly::new();

        // [첫 번째 테스트]
        // poly1 = X
        poly1.coeffs[1] = 1;
        // poly2 = X^63
        poly2.coeffs[63] = 1;

        // X * X^63 = X^64 = -1 = 256 (mod 257)
        let result1 = poly1.mul_naive(&poly2);
        assert_eq!(result1.coeffs[0], 256); 
        assert_eq!(result1.coeffs[1], 0);

        // 🚨 수정된 부분: 두 번째 테스트를 위해 다항식을 빈 상태로 초기화합니다.
        poly1 = SwifftPoly::new();
        poly2 = SwifftPoly::new();

        // [두 번째 복합 연산 테스트]
        // poly1 = 2 + 3X
        poly1.coeffs[0] = 2;
        poly1.coeffs[1] = 3;
        
        // poly2 = 4 + 5X
        poly2.coeffs[0] = 4;
        poly2.coeffs[1] = 5;

        // (2+3X) * (4+5X) = 8 + 10X + 12X + 15X^2 = 8 + 22X + 15X^2
        let result2 = poly1.mul_naive(&poly2);
        assert_eq!(result2.coeffs[0], 8);
        assert_eq!(result2.coeffs[1], 22);
        assert_eq!(result2.coeffs[2], 15);
    }
}
pub mod sha256;