// src/bin/air_mulmod.rs
//
// AIR-1 (1단계): 단일 게이트 G2 MULMOD 의 AIR 제약 + uni-stark 라운드트립.
//
// config 셋업은 이 프로젝트에서 *실제로 컴파일·동작하는* prove_bench.rs 의
// 패턴을 그대로 복사했다(추측 금지). 이전 빌드 실패는 검색 기반 옛 예제 API
// 를 따라서였고, 이번엔 동일 plonky3 리비전(64b3cc0)에서 작동 확인된 타입만
// 사용한다.
//
// 증명 대상: r == (u*f) mod 257.
// 컬럼(width=22): 0 u | 1 f | 2 prod | 3 k | 4 r | 5..12 r_low 8비트 |
//                 13 r_top | 14..21 k 8비트
// 제약 (Python 검증: completeness 20만 / soundness 위조거부 / degree 2):
//   M1 : prod - u*f = 0
//   M2 : prod - 257*k - r = 0
//   M3a: r - r_low - 256*r_top = 0   (r_low = Σ r_bit_i 2^i, i=0..7)
//   M3b: 각 r_bit ∈ {0,1} ; M3c: r_top ∈ {0,1}
//   M3d: r_top * r_low = 0           (=> r ∈ [0,256], soundness 핵심)
//   M4a: k - k_val = 0 ; M4b: 각 k_bit ∈ {0,1}  (=> k ∈ [0,255])
//
// 검증: (1) 정직 trace → prove+verify 성공(completeness),
//       (2) 위조 trace(틀린 r) → prove 패닉 또는 verify 실패(soundness 실측).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing; // ZERO / ONE (컴파일러 확인 경로)
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};

// ── API 출처 (전부 작동 확인된 코드 / 컴파일러 메시지 기준, 추측 없음) ──
//  - config/prove/verify : 이 프로젝트의 prove_bench.rs (컴파일·동작 확인)
//  - 행 접근 main.current(i).unwrap().clone().into() : 이 프로젝트의
//    Sha256BitwiseAir::eval (컴파일·동작 확인) + use p3_air::WindowAccess
//  - ZERO/ONE : p3_field::PrimeCharacteristicRing (컴파일러 확인)
//  - 정수 상수: 이 리비전엔 from_canonical_u32 없음 → ZERO/ONE/+ 누적으로
//    구성(제약부), trace 부는 컴파일러 지정 F::new(u32)
//  - bool 제약은 assert_bool 대신 bit*bit-bit=0 (sha256.rs 와 동일 형태)

const Q: i32 = 257;
const WIDTH: usize = 22;

const C_U: usize = 0;
const C_F: usize = 1;
const C_PROD: usize = 2;
const C_K: usize = 3;
const C_R: usize = 4;
const C_RLOW_BITS: usize = 5; // 5..13 (8개)
const C_RTOP: usize = 13;
const C_KBITS: usize = 14; // 14..22 (8개)

// ── 작동 확인된 config 타입 (prove_bench.rs 패턴 그대로) ──
type F = BabyBear;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type MyMmcs = MerkleTreeMmcs<F, u8, FieldHash, MyCompress, 2, 32>;
type MyDft = Radix2Bowers;
type MyPcs = TwoAdicFriPcs<F, MyDft, MyMmcs, MyMmcs>;
type ByteChallenger = HashChallenger<u8, ByteHash, 32>;
type MyChallenger = SerializingChallenger32<F, ByteChallenger>;
type MyConfig = StarkConfig<MyPcs, F, MyChallenger>;

fn make_config() -> MyConfig {
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(ByteHash {});
    let mmcs = MyMmcs::new(field_hash, compress, 32);
    let dft = MyDft::default();
    let fri_config = FriParameters {
        log_blowup: 1, // degree 2 제약 → log_blowup 1 로 충분(검색 BabyBear 사례)
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: mmcs.clone(),
    };
    let pcs = MyPcs::new(dft, mmcs, fri_config);
    let byte_challenger = ByteChallenger::new(vec![], ByteHash {});
    let challenger = MyChallenger::new(byte_challenger);
    MyConfig::new(pcs, challenger)
}

/// G2 MULMOD AIR.
pub struct MulModAir;

impl<FF> BaseAir<FF> for MulModAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for MulModAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        // 행 접근: 작동하는 Sha256BitwiseAir 와 동일하게 main.current(i).
        // (WindowAccess trait 이 제공. row_slice 는 이 리비전에 없음.)
        let col = |i: usize| -> AB::Expr {
            main.current(i).unwrap().clone().into()
        };

        let u = col(C_U);
        let f = col(C_F);
        let prod = col(C_PROD);
        let k = col(C_K);
        let r = col(C_R);
        let r_top = col(C_RTOP);

        // 상수: 이 리비전엔 AB::Expr::from_canonical_u32 가 없다.
        // 확인된 ZERO/ONE/+/clone 만으로 정수를 구성 (sha256.rs 가 호너법으로
        // 정수 상수 없이 큰 수를 만든 것과 동일 원리). 이진 누적으로 O(log n).
        let u32_expr = |n: u32| -> AB::Expr {
            let mut acc = AB::Expr::ZERO;
            let mut base = AB::Expr::ONE;
            let mut m = n;
            while m > 0 {
                if m & 1 == 1 {
                    acc = acc + base.clone();
                }
                base = base.clone() + base.clone();
                m >>= 1;
            }
            acc
        };
        let q: AB::Expr = u32_expr(257);
        let c256: AB::Expr = u32_expr(256);

        // M1: prod = u*f
        builder.assert_zero(prod.clone() - u * f);
        // M2: prod = 257*k + r
        builder.assert_zero(prod - (q * k.clone() + r.clone()));

        // r_low = Σ r_bit_i 2^i, 각 bit ∈ {0,1}
        let mut r_low = AB::Expr::ZERO;
        let mut pow = AB::Expr::ONE;
        for i in 0..8 {
            let bit = col(C_RLOW_BITS + i);
            // bool 제약: bit*bit - bit = 0 (작동 sha256.rs 와 동일 형태)
            builder.assert_zero(bit.clone() * bit.clone() - bit.clone());
            r_low = r_low + bit * pow.clone();
            pow = pow.clone() + pow;
        }
        // M3c: r_top bool
        builder.assert_zero(r_top.clone() * r_top.clone() - r_top.clone());
        // M3a: r = r_low + 256*r_top
        builder.assert_zero(r - (r_low.clone() + c256 * r_top.clone()));
        // M3d: r_top * r_low = 0  (=> r ∈ [0,256], soundness 핵심)
        builder.assert_zero(r_top * r_low);

        // k_val = Σ k_bit_i 2^i, 각 bit ∈ {0,1} ; M4: k = k_val (k ∈ [0,255])
        let mut k_val = AB::Expr::ZERO;
        let mut pow2 = AB::Expr::ONE;
        for i in 0..8 {
            let bit = col(C_KBITS + i);
            builder.assert_zero(bit.clone() * bit.clone() - bit.clone()); // M4b
            k_val = k_val + bit * pow2.clone();
            pow2 = pow2.clone() + pow2;
        }
        builder.assert_zero(k - k_val); // M4a
    }
}

fn honest_row(u: i32, f: i32) -> [i32; WIDTH] {
    let prod = u * f;
    let k = prod / Q;
    let r = prod % Q;
    let r_top = if r == 256 { 1 } else { 0 };
    let r_low = if r_top == 1 { 0 } else { r };
    let mut row = [0i32; WIDTH];
    row[C_U] = u;
    row[C_F] = f;
    row[C_PROD] = prod;
    row[C_K] = k;
    row[C_R] = r;
    for i in 0..8 {
        row[C_RLOW_BITS + i] = (r_low >> i) & 1;
        row[C_KBITS + i] = (k >> i) & 1;
    }
    row[C_RTOP] = r_top;
    row
}

fn trace_from_rows(rows: &[[i32; WIDTH]]) -> RowMajorMatrix<F> {
    let h = rows.len().next_power_of_two().max(2);
    let mut values = Vec::with_capacity(h * WIDTH);
    for row in rows {
        for &v in row.iter() {
            debug_assert!(v >= 0);
            // 이 리비전: BabyBear(=MontyField31)는 from_canonical_u32 가 없고
            // 컴파일러가 지정한 new(u32) 를 쓴다.
            values.push(F::new(v as u32));
        }
    }
    // 패딩 행 전부 0: u=f=0→prod=0,k=0,r=0,모든비트0 → 모든 제약 0=0 만족.
    for _ in rows.len()..h {
        for _ in 0..WIDTH {
            values.push(F::ZERO);
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}

fn main() {
    println!("AIR-1: G2 MULMOD (single-gate AIR, uni-stark roundtrip + soundness)\n");

    let pairs: Vec<(i32, i32)> = vec![
        (1, 1),
        (256, 256), // r==256 경계 (r_top=1)
        (15, 20),   // prod=300, k=1, r=43
        (200, 200),
        (256, 1),
        (0, 0),
        (123, 211),
        (250, 251),
    ];
    let rows: Vec<[i32; WIDTH]> =
        pairs.iter().map(|&(u, f)| honest_row(u, f)).collect();

    // ── (1) 정직 trace: prove → verify 성공해야 함 (completeness) ──
    {
        let trace = trace_from_rows(&rows);
        let config = make_config();
        let air = MulModAir;
        let proof = prove::<MyConfig, _>(&config, &air, trace, &[]);
        match verify(&config, &air, &proof, &[]) {
            Ok(()) => {
                println!("[1] honest trace: prove + verify -> OK (completeness)")
            }
            Err(e) => {
                println!("[1] honest trace verify FAILED: {e:?}");
                std::process::exit(1);
            }
        }
    }

    // ── (2) 위조 trace: r 을 일부러 틀리게 → verify 가 반드시 실패 (soundness) ──
    {
        let mut bad = rows.clone();
        let idx = 2; // (15,20): 정답 r=43. 위조 r=44.
        bad[idx][C_R] = 44;
        for i in 0..8 {
            bad[idx][C_RLOW_BITS + i] = (44 >> i) & 1;
        }
        bad[idx][C_RTOP] = 0;
        // prod=300, k=1 그대로 → M2: 300 - 257 - 44 = -1 ≠ 0 → 어떤 k 로도 불가.

        let trace = trace_from_rows(&bad);
        let config = make_config();
        let air = MulModAir;
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let proof = prove::<MyConfig, _>(&config, &air, trace, &[]);
            verify(&config, &air, &proof, &[])
        }));
        match res {
            Err(_) => println!(
                "[2] forged trace: prove panicked on constraint violation -> OK (soundness)"
            ),
            Ok(Err(_)) => println!(
                "[2] forged trace: verify rejected the proof -> OK (soundness)"
            ),
            Ok(Ok(())) => {
                println!("[2] forged trace VERIFIED as valid -> SOUNDNESS BROKEN (BUG!)");
                std::process::exit(2);
            }
        }
    }

    println!(
        "\nResult: G2 MULMOD AIR sound & complete on tested instances.\n\
         Next: same pattern for G1 (UNPACK) and G3 (BFLY), then compose\n\
         into the full SWIFFT AIR (design doc §6: AIR-1 → AIR-2 packing)."
    );
}