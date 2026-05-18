use p3_air::{Air, AirBuilder, BaseAir, WindowAccess}; // WindowAccess 추가
use p3_field::{Field, PrimeCharacteristicRing};
use p3_field::integers::QuotientMap;
use p3_matrix::dense::RowMajorMatrix;
// p3_matrix::Matrix 는 이제 불필요 (row_slice 안 씀)

const A_BITS: usize = 0;
const B_BITS: usize = 32;
const C_BITS: usize = 64;
const A_VAL: usize = 96;
pub const SHA256_BITWISE_COLS: usize = 97;

pub struct Sha256BitwiseAir;

impl<F> BaseAir<F> for Sha256BitwiseAir {
    fn width(&self) -> usize {
        SHA256_BITWISE_COLS
    }
}

impl<AB: AirBuilder> Air<AB> for Sha256BitwiseAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice(); // &[AB::Var], row_slice 대체

        // 1. Boolean: a, b, c 비트는 0 또는 1
        for i in 0..32 {
            let a = local[A_BITS + i];
            let b = local[B_BITS + i];
            let c = local[C_BITS + i];
            builder.assert_zero(a * a - a);
            builder.assert_zero(b * b - b);
            builder.assert_zero(c * c - c);
        }

        // 2. Recomposition: a 비트 재구성값 == a 정수값
        let mut recomposed: AB::Expr = local[A_BITS + 31].into();
        for i in (0..31).rev() {
            let bit: AB::Expr = local[A_BITS + i].into();
            recomposed = recomposed.clone() + recomposed.clone() + bit;
        }
        let original_a: AB::Expr = local[A_VAL].into();
        builder.assert_zero(recomposed - original_a);

        // 3. XOR: c == a + b - 2ab
        let two = AB::Expr::ONE + AB::Expr::ONE;
        for i in 0..32 {
            let a: AB::Expr = local[A_BITS + i].into();
            let b: AB::Expr = local[B_BITS + i].into();
            let c: AB::Expr = local[C_BITS + i].into();
            let xor = a.clone() + b.clone() - two.clone() * a * b;
            builder.assert_zero(c - xor);
        }
    }
}

fn decompose_u32_to_bits<F: PrimeCharacteristicRing>(value: u32) -> [F; 32] {
    let mut bits = std::array::from_fn(|_| F::ZERO);
    for (i, b) in bits.iter_mut().enumerate() {
        if (value >> i) & 1 == 1 {
            *b = F::ONE;
        }
    }
    bits
}

pub fn generate_sha256_trace<F>(num_rows: usize) -> RowMajorMatrix<F>
where
    F: Field + PrimeCharacteristicRing + QuotientMap<u32>,
{
    assert!(
        num_rows.is_power_of_two(),
        "STARK trace height must be a power of two, got {num_rows}"
    );

    let mut values: Vec<F> = Vec::with_capacity(num_rows * SHA256_BITWISE_COLS);

    let mut a: u32 = 0x6a09_e667;
    let mut b: u32 = 0xbb67_ae85;

    for _ in 0..num_rows {
        let c = a ^ b;
        let a_bits = decompose_u32_to_bits::<F>(a);
        let b_bits = decompose_u32_to_bits::<F>(b);
        let c_bits = decompose_u32_to_bits::<F>(c);

        values.extend_from_slice(&a_bits);
        values.extend_from_slice(&b_bits);
        values.extend_from_slice(&c_bits);
        values.push(F::from_int(a));

        a = a.wrapping_add(1);
        b = b.wrapping_add(2);
    }

    RowMajorMatrix::new(values, SHA256_BITWISE_COLS)
}