// src/bin/air_swifft_unified.rs
//
// AIR-1 (4단계, 길 B): 통합 SWIFFT AIR — G1/G2/G3 를 selector 로 묶는다.
// 작은 합성 trace(G1/G2/G3 혼합 + 패딩)로 통합 AIR 의 prove/verify +
// selector soundness 를 먼저 확정한다(전체 trace_swifft.rs 확장은 다음 단계).
//
// plonky3 패턴(config / WindowAccess / u32_expr / main.current / F::new /
// assert_zero)은 검증 완료된 air_mulmod/unpack/bfly 와 동일(추측 없음).
// when(sel) API 는 이 리비전 미검증 → 검증된 assert_zero 로 sel*C=0 직접 표현
// (sel∈{0,1} 이므로 when(sel){C=0} 과 수학적 동치).
//
// 컬럼(width=48): 0 sel_u | 1 sel_m | 2 sel_b | 3.. payload(게이트별, 최대45)
//   G1 payload: 3 byte | 4..7 c0..c3 | 8..15 (hi0,lo0,..,hi3,lo3)
//   G2 payload: 3 u|4 f|5 prod|6 k|7 r|8..15 r_low8|16 r_top|17..24 k8
//   G3 payload: 3 a|4 b|5 w|6 prod|7 k1|8 v|9 lo|10 hi|11 flo|12 fhi|
//               13..20 v_low8|21 v_top|22..29 k1_8|30..37 lo_low8|38 lo_top|
//               39..46 hi_low8|47 hi_top
//
// 통합 제약 (Python 검증: completeness 혼합2050 / soundness 5공격 거부 / deg3):
//   S1: sel_u, sel_m, sel_b ∈ {0,1}  (bool)
//   S2: sel_u + sel_m + sel_b = 1     (soundness 핵심: 게이트우회/위장 차단)
//   각 게이트 제약 C 에 대해  sel_x * C = 0  (sel_x=1 일 때만 C 강제)
//   패딩행 = 유효한 G1 NOP (sel_u=1, byte=0) → G1 제약 자동만족 + S2 충족
//
// 검증: (1) 혼합 정직 trace → prove+verify 성공,
//       (2) 5가지 selector 우회/위조 공격 → 전부 verify 실패(soundness 실측).

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
const WIDTH: usize = 48;
const SU: usize = 0;
const SM: usize = 1;
const SB: usize = 2;
const P: usize = 3; // payload base

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
        // 통합 degree=3 (곱제약×selector) → log_blowup 2 (단독 게이트는 1이었음)
        log_blowup: 2,
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

pub struct SwifftUnifiedAir;

impl<FF> BaseAir<FF> for SwifftUnifiedAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for SwifftUnifiedAir {
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

        let su = col(SU);
        let sm = col(SM);
        let sb = col(SB);

        // S1: selector bool
        builder.assert_zero(su.clone() * su.clone() - su.clone());
        builder.assert_zero(sm.clone() * sm.clone() - sm.clone());
        builder.assert_zero(sb.clone() * sb.clone() - sb.clone());
        // S2: 합 = 1  (soundness 핵심 — 게이트 우회/위장/패딩위장 전부 차단)
        builder.assert_zero(
            su.clone() + sm.clone() + sb.clone() - AB::Expr::ONE,
        );

        let q = u32_expr(257);
        let c4 = u32_expr(4);
        let c16 = u32_expr(16);
        let c64 = u32_expr(64);
        let c256 = u32_expr(256);
        let two = u32_expr(2);

        // ── G1 제약 (sel_u 가드: su * C = 0) ──
        {
            let byte = col(P);
            let c0 = col(P + 1);
            let c1 = col(P + 2);
            let c2 = col(P + 3);
            let c3 = col(P + 4);
            // U1: su * (byte - (c0+4c1+16c2+64c3)) = 0
            builder.assert_zero(
                su.clone()
                    * (byte
                        - (c0.clone()
                            + c4.clone() * c1.clone()
                            + c16.clone() * c2.clone()
                            + c64.clone() * c3.clone())),
            );
            let cs = [c0, c1, c2, c3];
            for k in 0..4 {
                let hi = col(P + 5 + 2 * k);
                let lo = col(P + 6 + 2 * k);
                // U3: su * bool(hi), su * bool(lo)
                builder.assert_zero(
                    su.clone() * (hi.clone() * hi.clone() - hi.clone()),
                );
                builder.assert_zero(
                    su.clone() * (lo.clone() * lo.clone() - lo.clone()),
                );
                // U2: su * (c_k - (2 hi + lo)) = 0
                builder.assert_zero(
                    su.clone()
                        * (cs[k].clone()
                            - (two.clone() * hi + lo)),
                );
            }
        }

        // ── G2 제약 (sel_m 가드: sm * C = 0) ──
        {
            let u = col(P);
            let f = col(P + 1);
            let prod = col(P + 2);
            let k = col(P + 3);
            let r = col(P + 4);
            let r_top = col(P + 13);
            // M1: sm*(prod - u*f)
            builder.assert_zero(
                sm.clone() * (prod.clone() - u * f),
            );
            // M2: sm*(prod - 257k - r)
            builder.assert_zero(
                sm.clone()
                    * (prod - (q.clone() * k.clone() + r.clone())),
            );
            // r_low = Σ r_bit 2^i, sm*bool
            let mut r_low = AB::Expr::ZERO;
            let mut pw = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 5 + i);
                builder.assert_zero(
                    sm.clone()
                        * (bit.clone() * bit.clone() - bit.clone()),
                );
                r_low = r_low + bit * pw.clone();
                pw = pw.clone() + pw.clone();
            }
            builder.assert_zero(
                sm.clone()
                    * (r_top.clone() * r_top.clone() - r_top.clone()),
            );
            // M3a: sm*(r - r_low - 256 r_top)
            builder.assert_zero(
                sm.clone()
                    * (r.clone()
                        - (r_low.clone()
                            + c256.clone() * r_top.clone())),
            );
            // M3d: sm*(r_top * r_low)  (=> r∈[0,256])
            builder
                .assert_zero(sm.clone() * (r_top * r_low));
            // M4: k = Σ k_bit 2^i, sm*bool ; sm*(k - k_val)
            let mut k_val = AB::Expr::ZERO;
            let mut pw2 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 14 + i);
                builder.assert_zero(
                    sm.clone()
                        * (bit.clone() * bit.clone() - bit.clone()),
                );
                k_val = k_val + bit * pw2.clone();
                pw2 = pw2.clone() + pw2.clone();
            }
            builder.assert_zero(sm.clone() * (k - k_val));
        }

        // ── G3 제약 (sel_b 가드: sb * C = 0) ──
        {
            let a = col(P);
            let b = col(P + 1);
            let w = col(P + 2);
            let prod = col(P + 3);
            let k1 = col(P + 4);
            let v = col(P + 5);
            let lo = col(P + 6);
            let hi = col(P + 7);
            let flo = col(P + 8);
            let fhi = col(P + 9);
            let v_top = col(P + 18);
            let lo_top = col(P + 35);
            let hi_top = col(P + 44);

            // B1: sb*(prod - w*b)
            builder.assert_zero(sb.clone() * (prod.clone() - w * b));
            // B2: sb*(prod - 257 k1 - v)
            builder.assert_zero(
                sb.clone()
                    * (prod - (q.clone() * k1.clone() + v.clone())),
            );
            // B3: v range (v_low 8bit bool, v_top bool, v_top*v_low=0)
            let mut v_low = AB::Expr::ZERO;
            let mut pw = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 10 + i);
                builder.assert_zero(
                    sb.clone()
                        * (bit.clone() * bit.clone() - bit.clone()),
                );
                v_low = v_low + bit * pw.clone();
                pw = pw.clone() + pw.clone();
            }
            builder.assert_zero(
                sb.clone()
                    * (v_top.clone() * v_top.clone() - v_top.clone()),
            );
            builder.assert_zero(
                sb.clone()
                    * (v.clone()
                        - (v_low.clone()
                            + c256.clone() * v_top.clone())),
            );
            builder
                .assert_zero(sb.clone() * (v_top * v_low));
            // Bk: k1 range
            let mut k1v = AB::Expr::ZERO;
            let mut pw2 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 19 + i);
                builder.assert_zero(
                    sb.clone()
                        * (bit.clone() * bit.clone() - bit.clone()),
                );
                k1v = k1v + bit * pw2.clone();
                pw2 = pw2.clone() + pw2.clone();
            }
            builder.assert_zero(sb.clone() * (k1 - k1v));
            // B6: flo,fhi bool
            builder.assert_zero(
                sb.clone() * (flo.clone() * flo.clone() - flo.clone()),
            );
            builder.assert_zero(
                sb.clone() * (fhi.clone() * fhi.clone() - fhi.clone()),
            );
            // B4: sb*(lo - (a + v - 257 flo))
            builder.assert_zero(
                sb.clone()
                    * (lo.clone()
                        - (a.clone() + v.clone()
                            - q.clone() * flo)),
            );
            // B5: sb*(hi - (a - v + 257 fhi))
            builder.assert_zero(
                sb.clone() * (hi.clone() - (a - v + q * fhi)),
            );
            // B7lo: lo range
            let mut lo_low = AB::Expr::ZERO;
            let mut pw3 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 27 + i);
                builder.assert_zero(
                    sb.clone()
                        * (bit.clone() * bit.clone() - bit.clone()),
                );
                lo_low = lo_low + bit * pw3.clone();
                pw3 = pw3.clone() + pw3.clone();
            }
            builder.assert_zero(
                sb.clone()
                    * (lo_top.clone() * lo_top.clone()
                        - lo_top.clone()),
            );
            builder.assert_zero(
                sb.clone()
                    * (lo
                        - (lo_low.clone()
                            + c256.clone() * lo_top.clone())),
            );
            builder
                .assert_zero(sb.clone() * (lo_top * lo_low));
            // B7hi: hi range
            let mut hi_low = AB::Expr::ZERO;
            let mut pw4 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 36 + i);
                builder.assert_zero(
                    sb.clone()
                        * (bit.clone() * bit.clone() - bit.clone()),
                );
                hi_low = hi_low + bit * pw4.clone();
                pw4 = pw4.clone() + pw4.clone();
            }
            builder.assert_zero(
                sb.clone()
                    * (hi_top.clone() * hi_top.clone()
                        - hi_top.clone()),
            );
            builder.assert_zero(
                sb.clone()
                    * (hi - (hi_low.clone() + c256 * hi_top.clone())),
            );
            builder.assert_zero(sb.clone() * (hi_top * hi_low));
        }
    }
}

// ── 정직 행 생성기 ──
fn mk_g1(byte: u8) -> [i32; WIDTH] {
    let b = byte as i32;
    let cs = [b & 3, (b >> 2) & 3, (b >> 4) & 3, (b >> 6) & 3];
    let mut r = [0i32; WIDTH];
    r[SU] = 1;
    r[P] = b;
    for k in 0..4 {
        r[P + 1 + k] = cs[k];
        r[P + 5 + 2 * k] = (cs[k] >> 1) & 1;
        r[P + 6 + 2 * k] = cs[k] & 1;
    }
    r
}

fn mk_g2(u: i32, f: i32) -> [i32; WIDTH] {
    let prod = u * f;
    let k = prod / Q;
    let rr = prod % Q;
    let mut r = [0i32; WIDTH];
    r[SM] = 1;
    r[P] = u;
    r[P + 1] = f;
    r[P + 2] = prod;
    r[P + 3] = k;
    r[P + 4] = rr;
    let rt = if rr == 256 { 1 } else { 0 };
    let rl = if rt == 1 { 0 } else { rr };
    for i in 0..8 {
        r[P + 5 + i] = (rl >> i) & 1;
        r[P + 14 + i] = (k >> i) & 1;
    }
    r[P + 13] = rt;
    r
}

fn dec(x: i32) -> ([i32; 8], i32) {
    let t = if x == 256 { 1 } else { 0 };
    let lw = if t == 1 { 0 } else { x };
    let mut bits = [0i32; 8];
    for i in 0..8 {
        bits[i] = (lw >> i) & 1;
    }
    (bits, t)
}

fn mk_g3(a: i32, b: i32, w: i32) -> [i32; WIDTH] {
    let prod = w * b;
    let k1 = prod / Q;
    let v = prod % Q;
    let s = a + v;
    let flo = if s >= Q { 1 } else { 0 };
    let lo = s - Q * flo;
    let d = a - v;
    let fhi = if d < 0 { 1 } else { 0 };
    let hi = d + Q * fhi;
    let mut r = [0i32; WIDTH];
    r[SB] = 1;
    r[P] = a;
    r[P + 1] = b;
    r[P + 2] = w;
    r[P + 3] = prod;
    r[P + 4] = k1;
    r[P + 5] = v;
    r[P + 6] = lo;
    r[P + 7] = hi;
    r[P + 8] = flo;
    r[P + 9] = fhi;
    let (vb, vt) = dec(v);
    for i in 0..8 {
        r[P + 10 + i] = vb[i];
    }
    r[P + 18] = vt;
    for i in 0..8 {
        r[P + 19 + i] = (k1 >> i) & 1;
    }
    let (lb, lt) = dec(lo);
    for i in 0..8 {
        r[P + 27 + i] = lb[i];
    }
    r[P + 35] = lt;
    let (hb, ht) = dec(hi);
    for i in 0..8 {
        r[P + 36 + i] = hb[i];
    }
    r[P + 44] = ht;
    r
}

fn mk_pad() -> [i32; WIDTH] {
    mk_g1(0) // 패딩 = 유효한 G1 NOP (S2 충족 + G1 제약 자동만족)
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
    // 패딩 = G1 NOP (전부-0 아님: S2 합=1 을 지켜야 하므로)
    let pad = mk_pad();
    for _ in rows.len()..h {
        for &v in pad.iter() {
            values.push(F::new(v as u32));
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}

fn run(label: &str, rows: &[[i32; WIDTH]], expect_ok: bool) {
    let trace = trace_from_rows(rows);
    let config = make_config();
    let air = SwifftUnifiedAir;
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = prove::<MyConfig, _>(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[])
    }));
    let passed_verify = matches!(res, Ok(Ok(())));
    if expect_ok {
        if passed_verify {
            println!("[1] {label}: prove+verify -> OK (completeness)");
        } else {
            println!("[1] {label}: honest trace FAILED verify -> BUG");
            std::process::exit(1);
        }
    } else {
        // soundness: 위조는 verify 실패(또는 prove 패닉)해야 정상
        if passed_verify {
            println!("[2] {label}: forged VERIFIED -> SOUNDNESS BROKEN (BUG!)");
            std::process::exit(2);
        } else {
            println!("[2] {label}: forged rejected -> OK (soundness)");
        }
    }
}

fn main() {
    println!("AIR-1 (path B): unified SWIFFT AIR — small mixed trace\n");

    // ── (1) 혼합 정직 trace: G1/G2/G3 + 패딩 ──
    let honest: Vec<[i32; WIDTH]> = vec![
        mk_g1(182),
        mk_g2(15, 20),
        mk_g3(200, 100, 1),
        mk_g1(255),
        mk_g2(256, 256),
        mk_g3(123, 45, 200),
        mk_g1(0),
        mk_g2(250, 251),
        mk_g3(255, 255, 2),
        mk_pad(),
        mk_pad(),
    ];
    run("honest mixed", &honest, true);

    // ── (2) soundness: 5가지 selector 우회/위조 공격 (Python 검증 케이스) ──
    // A: sel 전부 0 (게이트 우회) — S2 합=1 위반
    {
        let mut bad = honest.clone();
        bad[1][SM] = 0; // G2 행의 sel 제거 → 합=0
        run("attack A (all sel=0)", &bad, false);
    }
    // B: sel_m=1 인데 r 위조 — G2 제약 위반
    {
        let mut bad = honest.clone();
        bad[1][P + 4] = 44; // r: 43 → 44 (M2 깨짐)
        run("attack B (forge r)", &bad, false);
    }
    // C: sel 두 개 1 (분수 공격) — S2 위반
    {
        let mut bad = honest.clone();
        bad[1][SU] = 1; // sel_m=1 인데 sel_u 도 1 → 합=2
        run("attack C (two sel=1)", &bad, false);
    }
    // D: G2 행을 sel_b=1 로 위장 — G3 제약이 G2 payload 거부
    {
        let mut bad = honest.clone();
        bad[1][SM] = 0;
        bad[1][SB] = 1; // G2 payload 에 G3 제약 적용 → 위반
        run("attack D (G2 as sel_b)", &bad, false);
    }
    // E: 진짜 G3 행을 전부-0 으로 (패딩 위장) — S2 합=0 위반
    {
        let mut bad = honest.clone();
        bad[2] = [0i32; WIDTH]; // G3 행 → all-0 (sel 합=0)
        run("attack E (G3 as all-0)", &bad, false);
    }

    println!(
        "\nResult: unified SWIFFT AIR sound & complete on the small mixed\n\
         trace. Selector design (S1 bool + S2 sum=1 + sel*C guards) holds.\n\
         Next (path A): widen trace_swifft.rs to width=48 and feed the\n\
         full SWIFFT trace through this AIR (design doc §6 AIR-1 done)."
    );
}