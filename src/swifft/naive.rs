// src/swifft/naive.rs

/// SWIFFT에서 사용하는 모듈러스 (q = 257)
pub const SWIFFT_MODULUS: u16 = 257;

/// 다항식의 최대 차수 (N = 64)
pub const SWIFFT_DEGREE: usize = 64;

/// SWIFFT에서 사용하는 다항식의 개수 (m = 16)
pub const SWIFFT_M: usize = 16;

/// SWIFFT 다항식 구조체 (Naive 버전)
/// 64개의 계수를 가지며, 정상 사용 시 각 계수는 0 ~ 256 사이의 값입니다.
/// (coeffs 는 pub 필드라 외부에서 임의 u16 대입이 가능하므로,
///  mul_naive 는 비정규화 입력에서도 오버플로가 없도록 설계되어 있습니다.)
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SwifftPolyNaive {
    pub coeffs: [u16; SWIFFT_DEGREE],
}

impl SwifftPolyNaive {
    /// 모든 계수가 0인 빈 다항식을 생성합니다.
    pub fn new() -> Self {
        SwifftPolyNaive {
            coeffs: [0; SWIFFT_DEGREE],
        }
    }

    /// 두 다항식을 더합니다. (a + b) mod 257
    ///
    /// 주의: 이 덧셈은 두 계수가 정규화 범위 [0, 256] 일 때만
    /// u16 오버플로가 없습니다(합 최대 512). 외부에서 비정규화된
    /// 큰 u16 값을 직접 넣은 경우는 호출자가 책임집니다. SWIFFT
    /// 정상 경로(키/입력/누적 결과 모두 [0,256])에서는 항상 안전합니다.
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..SWIFFT_DEGREE {
            result.coeffs[i] = (self.coeffs[i] + other.coeffs[i]) % SWIFFT_MODULUS;
        }
        result
    }

    /// O(N^2) 기본 다항식 곱셈 (X^64 + 1 negacyclic 축소 포함).
    ///
    /// [개선] 누적 버퍼를 u64 로 사용한다.
    /// 한 항의 최대값은 u16^2 = 65535^2 ≈ 4.29e9 이고, 한 계수 위치에
    /// 누적되는 항은 최대 64개이므로 최악 누적값은 64 * 65535^2 ≈ 2.75e11.
    /// 이는 u64::MAX(≈1.8e19) 에 비해 충분히 작아, coeffs 에 어떤 u16
    /// 값이 들어와도 오버플로가 발생하지 않는다. (이전 u32 버전은
    /// 비정규화 입력에서 오버플로 위험이 있었다.)
    pub fn mul_naive(&self, other: &Self) -> Self {
        let mut result = Self::new();
        // 버퍼 크기를 2배(128)로 잡아 내부 분기문을 제거.
        let mut temp = [0u64; SWIFFT_DEGREE * 2];

        // O(N^2) 누적: 곱셈과 배열 덧셈만 수행.
        for i in 0..SWIFFT_DEGREE {
            for j in 0..SWIFFT_DEGREE {
                temp[i + j] += (self.coeffs[i] as u64) * (other.coeffs[j] as u64);
            }
        }

        // 루프 밖에서 한 번만 Negacyclic 축소(X^64 = -1) + 모듈러.
        let q = SWIFFT_MODULUS as u64;
        for i in 0..SWIFFT_DEGREE {
            let lower = temp[i] % q;
            let upper = temp[i + SWIFFT_DEGREE] % q;
            // X^64 = -1 이므로 하위에서 상위를 뺀다.
            // 음수 방지를 위해 q 를 더한 뒤 다시 모듈러.
            let val = (lower + q - upper) % q;
            result.coeffs[i] = val as u16;
        }

        result
    }
}

impl Default for SwifftPolyNaive {
    fn default() -> Self {
        Self::new()
    }
}

/// SWIFFT 해시 인스턴스 (Naive 버전)
/// 시스템 파라미터로 16개의 고정된 무작위 다항식(키)을 가집니다.
pub struct SwifftHasherNaive {
    pub keys: [SwifftPolyNaive; SWIFFT_M],
}

impl SwifftHasherNaive {
    /// 벤치마크를 위해 임의의 키 값을 가진 해시 인스턴스를 생성합니다.
    pub fn new() -> Self {
        let mut keys = [SwifftPolyNaive::new(); SWIFFT_M];
        for i in 0..SWIFFT_M {
            for j in 0..SWIFFT_DEGREE {
                // 테스트용 더미 난수 (i * j mod 257) — 항상 [0,256].
                keys[i].coeffs[j] = ((i * j) % (SWIFFT_MODULUS as usize)) as u16;
            }
        }
        Self { keys }
    }

    /// 16개의 입력 다항식을 받아 1개의 다항식으로 해싱(압축)합니다.
    /// out = sum_i ( keys[i] (*) inputs[i] )  (negacyclic, X^64 + 1)
    pub fn compress(&self, inputs: &[SwifftPolyNaive; SWIFFT_M]) -> SwifftPolyNaive {
        let mut result = SwifftPolyNaive::new();

        for i in 0..SWIFFT_M {
            let term = self.keys[i].mul_naive(&inputs[i]);
            // 제자리 누적 (term 의 계수는 mul_naive 가 [0,256] 으로 환원함).
            for j in 0..SWIFFT_DEGREE {
                result.coeffs[j] =
                    (result.coeffs[j] + term.coeffs[j]) % SWIFFT_MODULUS;
            }
        }

        result
    }
}

impl Default for SwifftHasherNaive {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------
// 로직이 수학적으로 올바른지 검증하는 유닛 테스트
// -------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_mul_naive() {
        let mut poly1 = SwifftPolyNaive::new();
        let mut poly2 = SwifftPolyNaive::new();

        // poly1 = X, poly2 = X^63
        poly1.coeffs[1] = 1;
        poly2.coeffs[63] = 1;

        // X * X^63 = X^64 = -1 = 256 (mod 257)
        let result1 = poly1.mul_naive(&poly2);
        assert_eq!(result1.coeffs[0], 256);
        assert_eq!(result1.coeffs[1], 0);

        poly1 = SwifftPolyNaive::new();
        poly2 = SwifftPolyNaive::new();

        // poly1 = 2 + 3X, poly2 = 4 + 5X
        poly1.coeffs[0] = 2;
        poly1.coeffs[1] = 3;
        poly2.coeffs[0] = 4;
        poly2.coeffs[1] = 5;

        // (2+3X)(4+5X) = 8 + 22X + 15X^2
        let result2 = poly1.mul_naive(&poly2);
        assert_eq!(result2.coeffs[0], 8);
        assert_eq!(result2.coeffs[1], 22);
        assert_eq!(result2.coeffs[2], 15);
    }

    /// [회귀] 비정규화된 최대 u16 계수에서도 오버플로/패닉 없이
    /// 수학적으로 올바른 결과(입력을 mod 257 한 것과 동일)를 내야 한다.
    /// 이전 u32 버퍼 버전이라면 디버그 빌드에서 패닉했을 입력이다.
    #[test]
    fn mul_naive_no_overflow_on_denormalized_input() {
        let mut a = SwifftPolyNaive::new();
        let mut b = SwifftPolyNaive::new();
        for k in 0..SWIFFT_DEGREE {
            a.coeffs[k] = u16::MAX; // 65535
            b.coeffs[k] = u16::MAX;
        }
        // 패닉/래핑 없이 완료되어야 함.
        let got = a.mul_naive(&b);

        // 기준: 입력을 먼저 mod 257 정규화한 negacyclic 곱.
        let q = SWIFFT_MODULUS as i64;
        let an: Vec<i64> = a.coeffs.iter().map(|&v| (v as i64) % q).collect();
        let bn: Vec<i64> = b.coeffs.iter().map(|&v| (v as i64) % q).collect();
        let mut expect = [0i64; SWIFFT_DEGREE];
        for i in 0..SWIFFT_DEGREE {
            for j in 0..SWIFFT_DEGREE {
                let p = an[i] * bn[j];
                let s = i + j;
                if s < SWIFFT_DEGREE {
                    expect[s] += p;
                } else {
                    expect[s - SWIFFT_DEGREE] -= p;
                }
            }
        }
        for i in 0..SWIFFT_DEGREE {
            assert_eq!(got.coeffs[i] as i64, expect[i].rem_euclid(q));
        }
    }

    /// mul_naive 의 negacyclic 규약이 ntt.rs / mod.rs 와 동일한지 확인.
    /// (정상 범위 [0,256] 입력에 대해.)
    #[test]
    fn negacyclic_convention_matches_definition() {
        let mut st = 0x9E3779B97F4A7C15u64;
        let mut next = || {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (st >> 33) as u32
        };

        for _ in 0..300 {
            let mut a = SwifftPolyNaive::new();
            let mut b = SwifftPolyNaive::new();
            for k in 0..SWIFFT_DEGREE {
                a.coeffs[k] = (next() % SWIFFT_MODULUS as u32) as u16;
                b.coeffs[k] = (next() % SWIFFT_MODULUS as u32) as u16;
            }
            let got = a.mul_naive(&b);

            // ntt.rs/mod.rs 가 쓰는 negacyclic 정의.
            let q = SWIFFT_MODULUS as i64;
            let mut expect = [0i64; SWIFFT_DEGREE];
            for i in 0..SWIFFT_DEGREE {
                for j in 0..SWIFFT_DEGREE {
                    let p = a.coeffs[i] as i64 * b.coeffs[j] as i64;
                    let s = i + j;
                    if s < SWIFFT_DEGREE {
                        expect[s] += p;
                    } else {
                        expect[s - SWIFFT_DEGREE] -= p;
                    }
                }
            }
            for i in 0..SWIFFT_DEGREE {
                assert_eq!(got.coeffs[i] as i64, expect[i].rem_euclid(q));
            }
        }
    }
}