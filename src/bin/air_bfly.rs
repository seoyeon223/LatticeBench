// src/bin/air_bfly.rs
//
// AIR-1 (3단계): 단일 게이트 G3 BFLY 의 AIR 제약 + uni-stark 라운드트립.
//
// plonky3 패턴(config / WindowAccess / u32_expr / main.current / F::new)은
// 검증 완료된 air_mulmod.rs / air_unpack.rs 와 동일하게 재사용(추측 없음).
// G3 는 세 게이트 중 가장 복잡: 곱 + 모듈러 환원 + 가감 보정 2개.
//
// 증명 대상: Stockham 버터플라이 1개 (ntt.rs reduce_mul/reduce_addsub 와 동일)
//   v  = (w*b) mod 257
//   lo = (a + v) mod 257
//   hi = (a - v) mod 257
//
// 컬럼(width=45):
//   0 a | 1 b | 2 w | 3 prod | 4 k1 | 5 v | 6 lo | 7 hi | 8 flo | 9 fhi
//   10..17 v_low(8bit) | 18 v_top
//   19..26 k1(8bit)
//   27..34 lo_low(8bit) | 35 lo_top
//   36..43 hi_low(8bit) | 44 hi_top
//
// 제약 (Python 검증: completeness 30만 / 값정확 / soundness 최선공격거부 / deg2):
//   B1 : prod - w*b = 0                                  (deg 2)
//   B2 : prod - 257*k1 - v = 0                           (deg 1)
//   B3 : v = v_low + 256*v_top ; 각 bit bool ; v_top*v_low=0  (v∈[0,256])
//   Bk : k1 = Σ k1_bit 2^i ; 각 bit bool                 (k1∈[0,255])
//   B4 : lo - (a + v - 257*flo) = 0 ; flo bool           (deg 1/2)
//   B5 : hi - (a - v + 257*fhi) = 0 ; fhi bool
//   B7lo: lo = lo_low + 256*lo_top ; bool ; lo_top*lo_low=0  (lo∈[0,256])
//   B7hi: hi 동일                                          (hi∈[0,256])
//   soundness 핵심: B3(v 범위) + B7lo/B7hi(lo/hi 범위). 없으면 flo/v 위조 가능.
//
// 검증: (1) 정직 trace → prove+verify 성공,
//       (2) 위조(flo 뒤집기) → verify 실패(soundness 실측).

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

const Q: i32 = 257;
const WIDTH: usize = 45;

const C_A: usize = 0;
const C_B: usize = 1;
const C_W: usize = 2;
const C_PROD: usize = 3;
const C_K1: usize = 4;
const C_V: usize = 5;
const C_LO: usize = 6;
const C_HI: usize = 7;
const C_FLO: usize = 8;
const C_FHI: usize = 9;
const C_VLOW: usize = 10; // 10..18
const C_VTOP: usize = 18;
const C_K1BITS: usize = 19; // 19..27
const C_LOLOW: usize = 27; // 27..35
const C_LOTOP: usize = 35;
const C_HILOW: usize = 36; // 36..44
const C_HITOP: usize = 44;

// ── 작동 확인된 config (air_mulmod.rs 와 동일) ──
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

pub struct BflyAir;

impl<FF> BaseAir<FF> for BflyAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for BflyAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let col = |i: usize| -> AB::Expr {
            main.current(i).unwrap().clone().into()
        };
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

        let a = col(C_A);
        let b = col(C_B);
        let w = col(C_W);
        let prod = col(C_PROD);
        let k1 = col(C_K1);
        let v = col(C_V);
        let lo = col(C_LO);
        let hi = col(C_HI);
        let flo = col(C_FLO);
        let fhi = col(C_FHI);
        let v_top = col(C_VTOP);
        let lo_top = col(C_LOTOP);
        let hi_top = col(C_HITOP);

        let q = u32_expr(257);
        let c256 = u32_expr(256);

        // B1: prod = w*b
        builder.assert_zero(prod.clone() - w * b);
        // B2: prod = 257*k1 + v
        builder.assert_zero(prod - (q.clone() * k1.clone() + v.clone()));

        // B3: v = v_low + 256*v_top ; v_low 8bit bool ; v_top bool ;
        //     v_top*v_low=0  (=> v∈[0,256], soundness 핵심)
        let mut v_low = AB::Expr::ZERO;
        let mut pw = AB::Expr::ONE;
        for i in 0..8 {
            let bit = col(C_VLOW + i);
            builder.assert_zero(bit.clone() * bit.clone() - bit.clone());
            v_low = v_low + bit * pw.clone();
            pw = pw.clone() + pw.clone();
        }
        builder.assert_zero(v_top.clone() * v_top.clone() - v_top.clone());
        builder.assert_zero(
            v.clone() - (v_low.clone() + c256.clone() * v_top.clone()),
        );
        builder.assert_zero(v_top * v_low);

        // Bk: k1 = Σ k1_bit 2^i ; bool  (=> k1∈[0,255])
        let mut k1_val = AB::Expr::ZERO;
        let mut pw2 = AB::Expr::ONE;
        for i in 0..8 {
            let bit = col(C_K1BITS + i);
            builder.assert_zero(bit.clone() * bit.clone() - bit.clone());
            k1_val = k1_val + bit * pw2.clone();
            pw2 = pw2.clone() + pw2.clone();
        }
        builder.assert_zero(k1 - k1_val);

        // B6: flo, fhi bool
        builder.assert_zero(flo.clone() * flo.clone() - flo.clone());
        builder.assert_zero(fhi.clone() * fhi.clone() - fhi.clone());

        // B4: lo = a + v - 257*flo
        builder.assert_zero(
            lo.clone() - (a.clone() + v.clone() - q.clone() * flo),
        );
        // B5: hi = a - v + 257*fhi
        builder.assert_zero(hi.clone() - (a - v + q * fhi));

        // B7lo: lo = lo_low + 256*lo_top ; bool ; lo_top*lo_low=0 (lo∈[0,256])
        let mut lo_low = AB::Expr::ZERO;
        let mut pw3 = AB::Expr::ONE;
        for i in 0..8 {
            let bit = col(C_LOLOW + i);
            builder.assert_zero(bit.clone() * bit.clone() - bit.clone());
            lo_low = lo_low + bit * pw3.clone();
            pw3 = pw3.clone() + pw3.clone();
        }
        builder
            .assert_zero(lo_top.clone() * lo_top.clone() - lo_top.clone());
        builder.assert_zero(
            lo - (lo_low.clone() + c256.clone() * lo_top.clone()),
        );
        builder.assert_zero(lo_top * lo_low);

        // B7hi: hi = hi_low + 256*hi_top ; bool ; hi_top*hi_low=0 (hi∈[0,256])
        let mut hi_low = AB::Expr::ZERO;
        let mut pw4 = AB::Expr::ONE;
        for i in 0..8 {
            let bit = col(C_HILOW + i);
            builder.assert_zero(bit.clone() * bit.clone() - bit.clone());
            hi_low = hi_low + bit * pw4.clone();
            pw4 = pw4.clone() + pw4.clone();
        }
        builder
            .assert_zero(hi_top.clone() * hi_top.clone() - hi_top.clone());
        builder.assert_zero(hi - (hi_low.clone() + c256 * hi_top.clone()));
        builder.assert_zero(hi_top * hi_low);
    }
}

fn dec(x: i32) -> ([i32; 8], i32) {
    // x ∈ [0,256] → (low 8bit, top)
    let t = if x == 256 { 1 } else { 0 };
    let lw = if t == 1 { 0 } else { x };
    let mut bits = [0i32; 8];
    for i in 0..8 {
        bits[i] = (lw >> i) & 1;
    }
    (bits, t)
}

fn honest_row(a: i32, b: i32, w: i32) -> [i32; WIDTH] {
    let prod = w * b;
    let k1 = prod / Q;
    let v = prod % Q;
    let s = a + v;
    let flo = if s >= Q { 1 } else { 0 };
    let lo = s - Q * flo;
    let d = a - v;
    let fhi = if d < 0 { 1 } else { 0 };
    let hi = d + Q * fhi;

    let mut row = [0i32; WIDTH];
    row[C_A] = a;
    row[C_B] = b;
    row[C_W] = w;
    row[C_PROD] = prod;
    row[C_K1] = k1;
    row[C_V] = v;
    row[C_LO] = lo;
    row[C_HI] = hi;
    row[C_FLO] = flo;
    row[C_FHI] = fhi;
    let (vb, vt) = dec(v);
    for i in 0..8 {
        row[C_VLOW + i] = vb[i];
    }
    row[C_VTOP] = vt;
    for i in 0..8 {
        row[C_K1BITS + i] = (k1 >> i) & 1;
    }
    let (lb, lt) = dec(lo);
    for i in 0..8 {
        row[C_LOLOW + i] = lb[i];
    }
    row[C_LOTOP] = lt;
    let (hb, ht) = dec(hi);
    for i in 0..8 {
        row[C_HILOW + i] = hb[i];
    }
    row[C_HITOP] = ht;
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
    // 패딩 행 전부 0: 모든 제약이 0=0 만족 (Python 검증).
    for _ in rows.len()..h {
        for _ in 0..WIDTH {
            values.push(F::ZERO);
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}

fn main() {
    println!("AIR-1: G3 BFLY (single-gate AIR, uni-stark roundtrip + soundness)\n");

    // 다양한 (a,b,w) + 경계(0, flo=1 케이스 등).
    let triples: Vec<(i32, i32, i32)> = vec![
        (200, 100, 1), // s=300>=257 → flo=1, lo=43
        (1, 1, 1),
        (0, 0, 0),
        (256, 256, 256),
        (123, 45, 200),
        (255, 255, 2),
        (50, 13, 81),
        (200, 200, 200),
    ];
    let rows: Vec<[i32; WIDTH]> = triples
        .iter()
        .map(|&(a, b, w)| honest_row(a, b, w))
        .collect();

    // ── (1) 정직 trace: prove → verify 성공 (completeness) ──
    {
        let trace = trace_from_rows(&rows);
        let config = make_config();
        let air = BflyAir;
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

    // ── (2) 위조 trace: (200,100,1) 의 flo 를 1→0 으로 뒤집고 lo 도 B4 맞춤 ──
    //     정답 flo=1,lo=43. 위조 flo=0 → B4 강제로 lo=a+v=300.
    //     공격자가 lo 분해를 '최선'으로(top=1,low=44, B7lo_a 만족하게) 맞춰도
    //     B7lo_d: lo_top*lo_low = 1*44 = 44 ≠ 0 으로 거부.
    //     (이는 v 범위제약과 동일한 soundness 메커니즘 — Python 검증 완료.)
    {
        let mut bad = rows.clone();
        let idx = 0; // (200,100,1)
        let a = 200;
        let v = bad[idx][C_V]; // 100
        bad[idx][C_FLO] = 0; // flo: 1 → 0
        let lo_bad = a + v - Q * 0; // = 300 (B4 만족)
        bad[idx][C_LO] = lo_bad;
        // 최선의 공격: top=1, low=44 (B7lo_a: 300-(44+256)=0 만족시킴).
        // 그러나 top*low = 44 ≠ 0 이라 B7lo_d 에서 거부된다.
        let lw = 44i32;
        for i in 0..8 {
            bad[idx][C_LOLOW + i] = (lw >> i) & 1;
        }
        bad[idx][C_LOTOP] = 1;

        let trace = trace_from_rows(&bad);
        let config = make_config();
        let air = BflyAir;
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
        "\nResult: G3 BFLY AIR sound & complete on tested instances.\n\
         All three gates (G1/G2/G3) verified. Next: compose them into the\n\
         full SWIFFT AIR with selectors (design doc §6: AIR-1 → AIR-2)."
    );
}