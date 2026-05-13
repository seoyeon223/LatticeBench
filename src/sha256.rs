use p3_air::{Air, AirBuilder, BaseAir};
use p3_air::WindowAccess; 
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

const SHA256_BITWISE_COLS: usize = 256; 

pub struct Sha256BitwiseAir;

impl<F> BaseAir<F> for Sha256BitwiseAir {
    fn width(&self) -> usize {
        SHA256_BITWISE_COLS
    }
}

impl<AB: AirBuilder> Air<AB> for Sha256BitwiseAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        // 1. Boolean 제약조건
        for i in 0..32 {
            let bit = main.current(i).unwrap().clone();
            builder.assert_zero(bit.clone() * bit.clone() - bit.clone());
        }

        // 2. Recomposition (호너의 방법)
        let mut recomposed_a: AB::Expr = main.current(31).unwrap().clone().into();
        for i in (0..31).rev() {
            let bit: AB::Expr = main.current(i).unwrap().clone().into();
            recomposed_a = recomposed_a.clone() + recomposed_a.clone() + bit;
        }
        let original_a: AB::Expr = main.current(32).unwrap().clone().into();
        builder.assert_zero(recomposed_a - original_a);

        // 3. 상태 전이 제약조건 (XOR)
        for i in 0..32 {
            let a_bit = main.current(i).unwrap().clone();
            let b_bit = main.current(33 + i).unwrap().clone();
            
            let expected_xor = a_bit.clone() + b_bit.clone() 
                - a_bit.clone() * b_bit.clone() 
                - a_bit.clone() * b_bit.clone();
            
            let next_c_bit: AB::Expr = main.next(66 + i).unwrap().clone().into();
            builder.assert_zero(next_c_bit - expected_xor);
        }
    }
}

// ---------------------------------------------------
// 🛠️ 비트 쪼개기 헬퍼 함수
// ---------------------------------------------------
// 💡 핵심: 최신 Plonky3의 Field 트레잇에 내장된 ZERO와 ONE 상수를 사용합니다!
pub fn decompose_u32_to_bits<F: Field>(value: u32) -> [F; 32] {
    let mut bits = [F::ZERO; 32];
    for i in 0..32 {
        if (value >> i) & 1 == 1 {
            bits[i] = F::ONE;
        }
    }
    bits
}

// ---------------------------------------------------
// 🚀 Trace Generator (실행 궤적 생성기)
// ---------------------------------------------------
pub fn generate_sha256_trace<F: Field>() -> RowMajorMatrix<F> {
    let mut trace_values: Vec<F> = Vec::new();
    let mut state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let num_rounds = 64; 

    for _round in 0..num_rounds {
        for &s in state.iter() {
            let bits = decompose_u32_to_bits::<F>(s);
            trace_values.extend(bits);
        }
        state[0] = state[0].wrapping_add(1); 
        state[1] = state[1].wrapping_add(2);
    }
    RowMajorMatrix::new(trace_values, SHA256_BITWISE_COLS)
}