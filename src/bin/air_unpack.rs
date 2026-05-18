// src/bin/air_unpack.rs
//
// AIR-1 (2단계): 단일 게이트 G1 UNPACK 의 AIR 제약 + uni-stark 라운드트립.
//
// plonky3 패턴(config / WindowAccess / u32_expr / main.current / F::new)은
// 검증 완료된 air_mulmod.rs 와 동일하게 재사용한다(추측 없음, API 씨름 끝).
// 이 파일은 제약 로직만 G1 으로 바뀐다.
//
// 증명 대상: byte → 4개 2비트 계수 c0..c3 의 정당한 분해.
// 컬럼(width=13): 0 byte | 1..4 c0..c3 | 5..12 (hi0,lo0,hi1,lo1,hi2,lo2,hi3,lo3)
// 제약 (Python 검증: completeness 전수 256 / soundness 위조거부 / degree 2):
//   U1 : byte - (c0 + 4*c1 + 16*c2 + 64*c3) = 0          (deg 1)
//   U2 : 각 k: c_k - (2*hi_k + lo_k) = 0                  (deg 1)
//   U3 : 각 비트 bit*bit - bit = 0 (bool)                 (deg 2)
//        => U3+U2 가 c_k ∈ {0,1,2,3} 강제(soundness 핵심), U1 이 byte 결속.
//
// 검증: (1) 정직 trace → prove+verify 성공(completeness),
//       (2) 위조 trace(byte 고정·c0 조작) → verify 실패(soundness 실측).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};

const WIDTH: usize = 13;
const C_BYTE: usize = 0;
const C_C: usize = 1; // 1..5 : c0..c3
const C_BITS: usize = 5; // 5..13 : (hi0,lo0,hi1,lo1,hi2,lo2,hi3,lo3)

// ── 작동 확인된 config (air_mulmod.rs 와 동일, prove_bench.rs 패턴) ──
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
        log_blowup: 1,
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

pub struct UnpackAir;

impl<FF> BaseAir<FF> for UnpackAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for UnpackAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let col = |i: usize| -> AB::Expr {
            main.current(i).unwrap().clone().into()
        };

        // 정수 상수 빌더 (air_mulmod.rs 와 동일: ZERO/ONE/+ 이진 누적).
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

        let byte = col(C_BYTE);
        let c0 = col(C_C);
        let c1 = col(C_C + 1);
        let c2 = col(C_C + 2);
        let c3 = col(C_C + 3);

        let w4 = u32_expr(4);
        let w16 = u32_expr(16);
        let w64 = u32_expr(64);
        let two = u32_expr(2);

        // U1: byte = c0 + 4*c1 + 16*c2 + 64*c3
        builder.assert_zero(
            byte - (c0.clone()
                + w4 * c1.clone()
                + w16 * c2.clone()
                + w64 * c3.clone()),
        );

        // U2 + U3: 각 c_k = 2*hi_k + lo_k, 각 비트 bool.
        let cs = [c0, c1, c2, c3];
        for k in 0..4 {
            let hi = col(C_BITS + 2 * k);
            let lo = col(C_BITS + 2 * k + 1);
            // U3: bool 제약 (sha256.rs 와 동일 형태 bit*bit - bit = 0)
            builder.assert_zero(hi.clone() * hi.clone() - hi.clone());
            builder.assert_zero(lo.clone() * lo.clone() - lo.clone());
            // U2: c_k - (2*hi + lo) = 0
            builder.assert_zero(
                cs[k].clone() - (two.clone() * hi + lo),
            );
        }
    }
}

fn honest_row(byte: u8) -> [i32; WIDTH] {
    let b = byte as i32;
    let cs = [b & 3, (b >> 2) & 3, (b >> 4) & 3, (b >> 6) & 3];
    let mut row = [0i32; WIDTH];
    row[C_BYTE] = b;
    for k in 0..4 {
        row[C_C + k] = cs[k];
        row[C_BITS + 2 * k] = (cs[k] >> 1) & 1; // hi_k
        row[C_BITS + 2 * k + 1] = cs[k] & 1; // lo_k
    }
    row
}

fn trace_from_rows(rows: &[[i32; WIDTH]]) -> RowMajorMatrix<F> {
    let h = rows.len().next_power_of_two().max(2);
    let mut values = Vec::with_capacity(h * WIDTH);
    for row in rows {
        for &v in row.iter() {
            debug_assert!(v >= 0);
            values.push(F::new(v as u32));
        }
    }
    // 패딩 행 전부 0: byte=0 → c=0, 모든 비트 0 → 모든 제약 0=0 만족.
    for _ in rows.len()..h {
        for _ in 0..WIDTH {
            values.push(F::ZERO);
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}

fn main() {
    println!("AIR-1: G1 UNPACK (single-gate AIR, uni-stark roundtrip + soundness)\n");

    // 다양한 바이트 + 경계값(0, 255, 패턴).
    let bytes: Vec<u8> = vec![0, 1, 3, 182, 255, 0xAB, 0x40, 0x7F];
    let rows: Vec<[i32; WIDTH]> =
        bytes.iter().map(|&b| honest_row(b)).collect();

    // ── (1) 정직 trace: prove → verify 성공 (completeness) ──
    {
        let trace = trace_from_rows(&rows);
        let config = make_config();
        let air = UnpackAir;
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

    // ── (2) 위조 trace: byte=182 고정, c0 을 2→0 으로 → U1 깨짐 → 실패 ──
    //     (Python 검증: c0 를 어떤 값으로 바꿔도 U1=0 불가 → soundness 케이스)
    {
        let mut bad = rows.clone();
        // index 3 == byte 182. 정답 cs=[2,1,3,2]. c0 을 0 으로 위조.
        let idx = 3;
        bad[idx][C_C] = 0; // c0: 2 -> 0
        bad[idx][C_BITS] = 0; // hi0 (U2,U3 는 맞춤)
        bad[idx][C_BITS + 1] = 0; // lo0
        // U1: 182 - (0 + 4*1 + 16*3 + 64*2) = 2 ≠ 0 → verify 실패 기대.

        let trace = trace_from_rows(&bad);
        let config = make_config();
        let air = UnpackAir;
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
        "\nResult: G1 UNPACK AIR sound & complete on tested instances.\n\
         Next: G3 BFLY (same pattern), then compose G1/G2/G3 into the\n\
         full SWIFFT AIR with selectors (design doc §6: AIR-1 → AIR-2)."
    );
}