// src/bin/trace_swifft.rs
//
// SWIFFT 전체 trace 생성 + 검증된 통합 AIR 로 prove/verify (AIR-1 완료)
// + STARK 증명 생성 peak 힙 메모리 측정 (mem_prove_* 와 동일 기준).
// + [추가] 게이트별 비용 분해 (논문 §"Why is SWIFFT expensive in STARK?")
//
// === 메모리 측정 관련 객관성 주의 (리포트에 반드시 명시) ===
// 이 측정의 config 는 SWIFFT AIR 가 *실제로 요구하는 최소값* 이다:
//   - log_blowup = 2  : 통합 AIR 제약 차수 3 → blowup 1 로는 검증 불가.
//                        (SHA/Keccak/Poseidon2 는 차수가 낮아 blowup 1.)
//   - height     = 32768 (2^15) : 1KB(4블록) trace 의 자연 크기.
//                        (SHA/Keccak/Poseidon2 는 2^14 로 통일.)
// 따라서 SWIFFT peak 메모리를 다른 셋과 절대값으로 직접 비교하면 안 된다.
// 각 측정은 "그 회로가 실제 배포 시 요구하는 최소 config 에서의 진짜
// 비용" 이며, 비교는 log_blowup/height 를 명시한 'config 보정 후'
// 상대 해석으로만 유효하다. (JSON 에 log_blowup/height/cells 동시 기록.)
//
// === [추가] 게이트별 비용 분해 (cost breakdown) ===
// 본 바이너리는 trace 생성 단계에서 각 게이트별 행 수를 카운트하고,
// MULMOD 행을 용도별로 세분화한다(PSI twist / 점별 곱 / N_INV / PSI_INV).
// 또한 "반사실 비용"을 추정한다: 모듈러스 257 ↔ BabyBear 미스매치로 인한
// 비트 분해(r_low 8bit + r_top + k 8bit, 컬럼 5..13, 14..21 → 17개 컬럼)가
// MULMOD 한 행의 width=48 중 얼마를 차지하는지. 이는 "SWIFFT 자체의 본질적
// 비용" vs "필드 미스매치의 부수적 비용"을 분리하는 정량 근거가 된다.
//
// 한 행 = 하나의 게이트. G1 UNPACK / G2 MULMOD / G3 BFLY.
// 출력 == SwifftHasherNaive(oracle) self-check 로 보장.

use p3_baby_bear::BabyBear;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};

use std::fs;
use std::hint::black_box;

use lattice_bench::swifft::ntt;
use lattice_bench::{SwifftHasherNaive, SwifftPolyNaive};

// dhat 힙 프로파일러 (mem_prove_sha256/keccak/poseidon2 와 동일 패턴).
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// ============================================================
//  검증된 통합 SWIFFT AIR (변경 없음)
// ============================================================
const Q: i32 = 257;
const WIDTH: usize = 48;
const SU: usize = 0;
const SM: usize = 1;
const SB: usize = 2;
const P: usize = 3;

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

// SWIFFT AIR 가 실제로 요구하는 검증된 config (변경 금지).
// log_blowup=2 는 degree-3 제약 때문에 필수 (낮추면 prove/verify 실패).
const SWIFFT_LOG_BLOWUP: usize = 2;

fn make_config() -> MyConfig {
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(ByteHash {});
    let mmcs = MyMmcs::new(field_hash, compress, 32);
    let dft = MyDft::default();
    let fri_config = FriParameters {
        log_blowup: SWIFFT_LOG_BLOWUP,
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
        let col = |i: usize| -> AB::Expr { main.current(i).unwrap().clone().into() };
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

        builder.assert_zero(su.clone() * su.clone() - su.clone());
        builder.assert_zero(sm.clone() * sm.clone() - sm.clone());
        builder.assert_zero(sb.clone() * sb.clone() - sb.clone());
        builder.assert_zero(su.clone() + sm.clone() + sb.clone() - AB::Expr::ONE);

        let q = u32_expr(257);
        let c4 = u32_expr(4);
        let c16 = u32_expr(16);
        let c64 = u32_expr(64);
        let c256 = u32_expr(256);
        let two = u32_expr(2);

        // ── G1 UNPACK ──
        {
            let byte = col(P);
            let c0 = col(P + 1);
            let c1 = col(P + 2);
            let c2 = col(P + 3);
            let c3 = col(P + 4);
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
                builder.assert_zero(su.clone() * (hi.clone() * hi.clone() - hi.clone()));
                builder.assert_zero(su.clone() * (lo.clone() * lo.clone() - lo.clone()));
                builder.assert_zero(
                    su.clone() * (cs[k].clone() - (two.clone() * hi + lo)),
                );
            }
        }

        // ── G2 MULMOD ──
        {
            let u = col(P);
            let f = col(P + 1);
            let prod = col(P + 2);
            let k = col(P + 3);
            let r = col(P + 4);
            let r_top = col(P + 13);
            builder.assert_zero(sm.clone() * (prod.clone() - u * f));
            builder.assert_zero(
                sm.clone() * (prod - (q.clone() * k.clone() + r.clone())),
            );
            let mut r_low = AB::Expr::ZERO;
            let mut pw = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 5 + i);
                builder.assert_zero(sm.clone() * (bit.clone() * bit.clone() - bit.clone()));
                r_low = r_low + bit * pw.clone();
                pw = pw.clone() + pw.clone();
            }
            builder.assert_zero(sm.clone() * (r_top.clone() * r_top.clone() - r_top.clone()));
            builder.assert_zero(
                sm.clone() * (r.clone() - (r_low.clone() + c256.clone() * r_top.clone())),
            );
            builder.assert_zero(sm.clone() * (r_top * r_low));
            let mut k_val = AB::Expr::ZERO;
            let mut pw2 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 14 + i);
                builder.assert_zero(sm.clone() * (bit.clone() * bit.clone() - bit.clone()));
                k_val = k_val + bit * pw2.clone();
                pw2 = pw2.clone() + pw2.clone();
            }
            builder.assert_zero(sm.clone() * (k - k_val));
        }

        // ── G3 BFLY ──
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

            builder.assert_zero(sb.clone() * (prod.clone() - w * b));
            builder.assert_zero(
                sb.clone() * (prod - (q.clone() * k1.clone() + v.clone())),
            );
            let mut v_low = AB::Expr::ZERO;
            let mut pw = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 10 + i);
                builder.assert_zero(sb.clone() * (bit.clone() * bit.clone() - bit.clone()));
                v_low = v_low + bit * pw.clone();
                pw = pw.clone() + pw.clone();
            }
            builder.assert_zero(sb.clone() * (v_top.clone() * v_top.clone() - v_top.clone()));
            builder.assert_zero(
                sb.clone() * (v.clone() - (v_low.clone() + c256.clone() * v_top.clone())),
            );
            builder.assert_zero(sb.clone() * (v_top * v_low));
            let mut k1v = AB::Expr::ZERO;
            let mut pw2 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 19 + i);
                builder.assert_zero(sb.clone() * (bit.clone() * bit.clone() - bit.clone()));
                k1v = k1v + bit * pw2.clone();
                pw2 = pw2.clone() + pw2.clone();
            }
            builder.assert_zero(sb.clone() * (k1 - k1v));
            builder.assert_zero(sb.clone() * (flo.clone() * flo.clone() - flo.clone()));
            builder.assert_zero(sb.clone() * (fhi.clone() * fhi.clone() - fhi.clone()));
            builder.assert_zero(
                sb.clone() * (lo.clone() - (a.clone() + v.clone() - q.clone() * flo)),
            );
            builder.assert_zero(sb.clone() * (hi.clone() - (a - v + q * fhi)));
            let mut lo_low = AB::Expr::ZERO;
            let mut pw3 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 27 + i);
                builder.assert_zero(sb.clone() * (bit.clone() * bit.clone() - bit.clone()));
                lo_low = lo_low + bit * pw3.clone();
                pw3 = pw3.clone() + pw3.clone();
            }
            builder.assert_zero(sb.clone() * (lo_top.clone() * lo_top.clone() - lo_top.clone()));
            builder.assert_zero(
                sb.clone() * (lo - (lo_low.clone() + c256.clone() * lo_top.clone())),
            );
            builder.assert_zero(sb.clone() * (lo_top * lo_low));
            let mut hi_low = AB::Expr::ZERO;
            let mut pw4 = AB::Expr::ONE;
            for i in 0..8 {
                let bit = col(P + 36 + i);
                builder.assert_zero(sb.clone() * (bit.clone() * bit.clone() - bit.clone()));
                hi_low = hi_low + bit * pw4.clone();
                pw4 = pw4.clone() + pw4.clone();
            }
            builder.assert_zero(sb.clone() * (hi_top.clone() * hi_top.clone() - hi_top.clone()));
            builder.assert_zero(sb.clone() * (hi - (hi_low.clone() + c256 * hi_top.clone())));
            builder.assert_zero(sb.clone() * (hi_top * hi_low));
        }
    }
}

const M: usize = 16;
const N: usize = 64;
const LOG_N: usize = 6;
const W: usize = 48;
const SEL_UNPACK: usize = 0;
const SEL_MULMOD: usize = 1;
const SEL_BFLY: usize = 2;
const PB: usize = 3;

// ============================================================
//  [추가] 게이트별 비용 분해 (cost breakdown)
// ============================================================
//
// MULMOD 행은 호출 위치에 따라 4가지 용도로 나뉜다.
// AIR 제약은 모두 동일하지만, "어디서 발생하는 비용인지" 를 알면
// SWIFFT 알고리즘의 어느 단계가 ZK 비용을 끌어올리는지 정량화할 수 있다.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MulmodKind {
    PsiTwist,    // x 청크의 PSI 비틀기 (16 청크 × 64 = 1024 행/블록)
    PointwiseMul, // 키와 점별 곱 (16 청크 × 64 = 1024 행/블록)
    NInvScale,   // 역NTT 후 N^{-1} 스케일링 (64 행/블록)
    PsiInvUntwist, // 최종 PSI^{-1} 역비틀기 (64 행/블록)
}

#[derive(Default, Debug, Clone)]
struct GateBreakdown {
    unpack_rows: usize,
    mulmod_rows_psi_twist: usize,
    mulmod_rows_pointwise: usize,
    mulmod_rows_ninv: usize,
    mulmod_rows_psi_inv: usize,
    bfly_rows_forward: usize,  // 정변환 NTT 의 버터플라이
    bfly_rows_inverse: usize,  // 역변환 NTT 의 버터플라이
}

impl GateBreakdown {
    fn mulmod_total(&self) -> usize {
        self.mulmod_rows_psi_twist
            + self.mulmod_rows_pointwise
            + self.mulmod_rows_ninv
            + self.mulmod_rows_psi_inv
    }
    fn bfly_total(&self) -> usize {
        self.bfly_rows_forward + self.bfly_rows_inverse
    }
    fn total_rows(&self) -> usize {
        self.unpack_rows + self.mulmod_total() + self.bfly_total()
    }
}

#[inline]
fn f(x: u32) -> BabyBear {
    BabyBear::new(x)
}

fn push_row(values: &mut Vec<BabyBear>, row: &[i32; W]) {
    for &v in row.iter() {
        debug_assert!(v >= 0, "trace value must be non-negative, got {v}");
        values.push(f(v as u32));
    }
}

fn g1_unpack(
    values: &mut Vec<BabyBear>,
    byte: u8,
    bd: &mut GateBreakdown,
) -> [i32; 4] {
    let b = byte as i32;
    let cs = [b & 3, (b >> 2) & 3, (b >> 4) & 3, (b >> 6) & 3];
    let mut row = [0i32; W];
    row[SEL_UNPACK] = 1;
    row[PB] = b;
    for k in 0..4 {
        row[PB + 1 + k] = cs[k];
        row[PB + 5 + 2 * k] = (cs[k] >> 1) & 1;
        row[PB + 6 + 2 * k] = cs[k] & 1;
    }
    push_row(values, &row);
    bd.unpack_rows += 1;
    cs
}

fn g2_mulmod(
    values: &mut Vec<BabyBear>,
    u: i32,
    fac: i32,
    bd: &mut GateBreakdown,
    kind: MulmodKind,
) -> i32 {
    let prod = u * fac;
    let k = prod / ntt::Q;
    let r = prod % ntt::Q;
    debug_assert!(prod == ntt::Q * k + r && (0..ntt::Q).contains(&r));
    let mut row = [0i32; W];
    row[SEL_MULMOD] = 1;
    row[PB] = u;
    row[PB + 1] = fac;
    row[PB + 2] = prod;
    row[PB + 3] = k;
    row[PB + 4] = r;
    let rt = if r == 256 { 1 } else { 0 };
    let rl = if rt == 1 { 0 } else { r };
    for i in 0..8 {
        row[PB + 5 + i] = (rl >> i) & 1;
        row[PB + 14 + i] = (k >> i) & 1;
    }
    row[PB + 13] = rt;
    push_row(values, &row);
    match kind {
        MulmodKind::PsiTwist => bd.mulmod_rows_psi_twist += 1,
        MulmodKind::PointwiseMul => bd.mulmod_rows_pointwise += 1,
        MulmodKind::NInvScale => bd.mulmod_rows_ninv += 1,
        MulmodKind::PsiInvUntwist => bd.mulmod_rows_psi_inv += 1,
    }
    r
}

fn g3_bfly(
    values: &mut Vec<BabyBear>,
    a: i32,
    b: i32,
    w: i32,
    bd: &mut GateBreakdown,
    inverse: bool,
) -> (i32, i32) {
    let prod = w * b;
    let k1 = prod / ntt::Q;
    let v = prod % ntt::Q;
    let s = a + v;
    let flo = if s >= ntt::Q { 1 } else { 0 };
    let lo = s - ntt::Q * flo;
    let d = a - v;
    let fhi = if d < 0 { 1 } else { 0 };
    let hi = d + ntt::Q * fhi;
    debug_assert!(lo == (a + v).rem_euclid(ntt::Q));
    debug_assert!(hi == (a - v).rem_euclid(ntt::Q));

    let dec = |x: i32| -> ([i32; 8], i32) {
        let t = if x == 256 { 1 } else { 0 };
        let lw = if t == 1 { 0 } else { x };
        let mut bits = [0i32; 8];
        for i in 0..8 {
            bits[i] = (lw >> i) & 1;
        }
        (bits, t)
    };

    let mut row = [0i32; W];
    row[SEL_BFLY] = 1;
    row[PB] = a;
    row[PB + 1] = b;
    row[PB + 2] = w;
    row[PB + 3] = prod;
    row[PB + 4] = k1;
    row[PB + 5] = v;
    row[PB + 6] = lo;
    row[PB + 7] = hi;
    row[PB + 8] = flo;
    row[PB + 9] = fhi;
    let (vb, vt) = dec(v);
    for i in 0..8 {
        row[PB + 10 + i] = vb[i];
    }
    row[PB + 18] = vt;
    for i in 0..8 {
        row[PB + 19 + i] = (k1 >> i) & 1;
    }
    let (lb, lt) = dec(lo);
    for i in 0..8 {
        row[PB + 27 + i] = lb[i];
    }
    row[PB + 35] = lt;
    let (hb, ht) = dec(hi);
    for i in 0..8 {
        row[PB + 36 + i] = hb[i];
    }
    row[PB + 44] = ht;
    push_row(values, &row);
    if inverse {
        bd.bfly_rows_inverse += 1;
    } else {
        bd.bfly_rows_forward += 1;
    }
    (lo, hi)
}

fn ntt_stage_traced(
    values: &mut Vec<BabyBear>,
    src: &[i32; N],
    tw: &[i32; N],
    l: usize,
    bd: &mut GateBreakdown,
    inverse: bool,
) -> [i32; N] {
    let m = N / (2 * l);
    let mut dst = [0i32; N];
    for k in 0..m {
        for j in 0..l {
            let w = tw[j * m];
            let a = src[k * l + j];
            let b = src[k * l + j + N / 2];
            let (lo, hi) = g3_bfly(values, a, b, w, bd, inverse);
            dst[2 * k * l + j] = lo;
            dst[2 * k * l + j + l] = hi;
        }
    }
    dst
}

fn ntt_traced(
    values: &mut Vec<BabyBear>,
    a: &[i32; N],
    inverse: bool,
    bd: &mut GateBreakdown,
) -> [i32; N] {
    let tw: &[i32; N] = if inverse {
        &ntt::OMEGA_INV_TABLE
    } else {
        &ntt::OMEGA_TABLE
    };
    let mut s = *a;
    let mut l = 1;
    for _ in 0..LOG_N {
        s = ntt_stage_traced(values, &s, tw, l, bd, inverse);
        l <<= 1;
    }
    if inverse {
        for j in 0..N {
            s[j] = g2_mulmod(values, s[j], ntt::N_INV, bd, MulmodKind::NInvScale);
        }
    }
    s
}

fn swifft_block_traced(
    values: &mut Vec<BabyBear>,
    data: &[u8],
    keys: &[[i32; N]; M],
    bd: &mut GateBreakdown,
) -> [i32; N] {
    let mut keys_ntt = [[0i32; N]; M];
    for i in 0..M {
        let mut kt = [0i32; N];
        for j in 0..N {
            kt[j] = (keys[i][j] * ntt::PSI_TABLE[j]).rem_euclid(ntt::Q);
        }
        ntt::ntt(&mut kt, false);
        keys_ntt[i] = kt;
    }

    let mut acc = [0i32; N];
    for i in 0..M {
        let chunk = &data[i * 16..(i + 1) * 16];
        let mut x = [0i32; N];
        for (jb, &byte) in chunk.iter().enumerate() {
            let cs = g1_unpack(values, byte, bd);
            x[jb * 4..jb * 4 + 4].copy_from_slice(&cs);
        }
        let mut xt = [0i32; N];
        for j in 0..N {
            xt[j] = g2_mulmod(values, x[j], ntt::PSI_TABLE[j], bd, MulmodKind::PsiTwist);
        }
        let xf = ntt_traced(values, &xt, false, bd);
        for j in 0..N {
            let p = g2_mulmod(values, xf[j], keys_ntt[i][j], bd, MulmodKind::PointwiseMul);
            acc[j] += p;
        }
    }
    for j in 0..N {
        acc[j] = acc[j].rem_euclid(ntt::Q);
    }
    let c = ntt_traced(values, &acc, true, bd);
    let mut out = [0i32; N];
    for j in 0..N {
        out[j] = g2_mulmod(values, c[j], ntt::PSI_INV_TABLE[j], bd, MulmodKind::PsiInvUntwist);
    }
    out
}

fn generate_swifft_trace(
    data: &[u8],
    keys: &[[i32; N]; M],
    bd: &mut GateBreakdown,
) -> RowMajorMatrix<BabyBear> {
    assert!(
        data.len() % 256 == 0 && !data.is_empty(),
        "input must be a non-empty multiple of 256 bytes"
    );
    let num_blocks = data.len() / 256;
    let mut values: Vec<BabyBear> = Vec::with_capacity(num_blocks * 5700 * W);

    for blk in 0..num_blocks {
        let _ = swifft_block_traced(
            &mut values,
            &data[blk * 256..(blk + 1) * 256],
            keys,
            bd,
        );
    }

    let rows_filled = values.len() / W;
    debug_assert_eq!(values.len() % W, 0, "row alignment broken");
    let padded = rows_filled.next_power_of_two();
    assert!(rows_filled <= padded);
    let mut nop = [0i32; W];
    nop[SEL_UNPACK] = 1;
    for _ in rows_filled..padded {
        for &v in nop.iter() {
            values.push(f(v as u32));
        }
    }

    RowMajorMatrix::new(values, W)
}

// ============================================================
//  [추가] 비용 분해 리포트 출력
// ============================================================
//
// 각 게이트가 width=48 컬럼 중 "필드 미스매치(모듈러스 257 ↔ BabyBear)"
// 때문에 강제되는 컬럼을 얼마나 쓰는지 정량화한다.
//
// G2 MULMOD (width=48):
//   - 산술 본질: u, f, prod, k, r (컬럼 PB..PB+4)              → 5 컬럼
//   - 모듈러 환원 강제 비트분해:
//       r_low 8bit + r_top + k 8bit (컬럼 PB+5..PB+21)         → 17 컬럼
//   - 미사용 패딩 (컬럼 PB+22..)                                → 나머지
//   * selector 3 컬럼 + 본질 5 = 정직한 "산술 비용" 8 컬럼
//   * 17 컬럼이 q=257 ≠ BabyBear 미스매치로 인한 부수 비용
//
// G3 BFLY (width=48):
//   - 산술 본질: a, b, w, prod, k1, v, lo, hi, flo, fhi      → 10 컬럼
//   - 비트분해 (v, k1, lo, hi 각 8bit + top):
//       (10..18 v_low8 + 18 v_top) + (19..27 k1_8) +
//       (27..35 lo_low8 + 35 lo_top) + (36..44 hi_low8 + 44 hi_top)
//                                                            → 34 컬럼
//   * 산술 본질 10 + selector 3 = 13 컬럼
//   * 34 컬럼이 미스매치로 인한 부수 비용
//
// 이 분해는 "SWIFFT 알고리즘 자체의 본질적 ZK 비용" 과
// "필드 미스매치의 부수적 비용" 을 정량적으로 분리한다.
// 논문의 핵심 통찰: ZK 친화 격자 해시 설계 시 필드 정합성이 1순위 변수.

const MULMOD_INTRINSIC_COLS: usize = 5;       // u, f, prod, k, r
const MULMOD_MISMATCH_COLS: usize = 17;       // r_low8 + r_top + k8
const BFLY_INTRINSIC_COLS: usize = 10;        // a,b,w,prod,k1,v,lo,hi,flo,fhi
const BFLY_MISMATCH_COLS: usize = 34;         // v/k1/lo/hi 각 비트분해 + top
const UNPACK_INTRINSIC_COLS: usize = 13;      // byte + 4 coeff + 4×(hi,lo)
const SELECTOR_COLS: usize = 3;               // su, sm, sb

fn print_cost_breakdown(bd: &GateBreakdown, num_blocks: usize, padded_rows: usize) {
    let total_logical = bd.total_rows();
    let padding_rows = padded_rows - total_logical;

    println!("\n┌──────────────────────────────────────────────────────────┐");
    println!(  "│  Gate-level Cost Breakdown (논문 §Analysis 용)            │");
    println!(  "└──────────────────────────────────────────────────────────┘");
    println!("Input: {num_blocks} block(s) × 256 B = {} B", num_blocks * 256);
    println!("Logical rows (no padding): {total_logical}");
    println!("Padded rows (next_pow2):   {padded_rows}");
    println!("Padding overhead:          {padding_rows} rows ({:.1}%)",
             100.0 * padding_rows as f64 / padded_rows as f64);
    println!();

    // 행 수 분해
    println!("── Row counts by gate ──");
    println!("  G1 UNPACK            : {:>8} rows ({:>5.1}%)",
             bd.unpack_rows,
             100.0 * bd.unpack_rows as f64 / total_logical as f64);
    println!("  G2 MULMOD (total)    : {:>8} rows ({:>5.1}%)",
             bd.mulmod_total(),
             100.0 * bd.mulmod_total() as f64 / total_logical as f64);
    println!("    ├─ PSI twist       : {:>8} rows (input pre-twist)",
             bd.mulmod_rows_psi_twist);
    println!("    ├─ pointwise mul   : {:>8} rows (key × x in NTT domain)",
             bd.mulmod_rows_pointwise);
    println!("    ├─ N^{{-1}} scale     : {:>8} rows (post-INTT)",
             bd.mulmod_rows_ninv);
    println!("    └─ PSI^{{-1}} untwist : {:>8} rows (final untwist)",
             bd.mulmod_rows_psi_inv);
    println!("  G3 BFLY (total)      : {:>8} rows ({:>5.1}%)",
             bd.bfly_total(),
             100.0 * bd.bfly_total() as f64 / total_logical as f64);
    println!("    ├─ forward NTT     : {:>8} rows (M chunks × 6 stages × 32)",
             bd.bfly_rows_forward);
    println!("    └─ inverse NTT     : {:>8} rows (1 INTT × 6 stages × 32)",
             bd.bfly_rows_inverse);
    println!();

    // 셀 수 분해 (padding 포함)
    let unpack_cells = bd.unpack_rows * W;
    let mulmod_cells = bd.mulmod_total() * W;
    let bfly_cells   = bd.bfly_total() * W;
    let padding_cells = padding_rows * W;
    let total_cells = padded_rows * W;

    println!("── Cell counts by gate (width={W}) ──");
    println!("  G1 UNPACK            : {:>10} cells ({:>5.1}%)",
             unpack_cells, 100.0 * unpack_cells as f64 / total_cells as f64);
    println!("  G2 MULMOD            : {:>10} cells ({:>5.1}%)",
             mulmod_cells, 100.0 * mulmod_cells as f64 / total_cells as f64);
    println!("  G3 BFLY              : {:>10} cells ({:>5.1}%)",
             bfly_cells, 100.0 * bfly_cells as f64 / total_cells as f64);
    println!("  padding (next_pow2)  : {:>10} cells ({:>5.1}%)",
             padding_cells, 100.0 * padding_cells as f64 / total_cells as f64);
    println!("  ─────────────────────  ──────────");
    println!("  TOTAL                : {:>10} cells", total_cells);
    println!();

    // ── 핵심: 필드 미스매치 vs 산술 본질 분해 ──
    //
    // 각 게이트의 컬럼을 "산술 본질" + "필드 미스매치 비트분해" + "selector"
    // 로 나눠 셀 수를 재합산한다. selector 컬럼은 미스매치와 무관하지만,
    // unified AIR 의 soundness 를 위해 필수이므로 별도 카운트.
    let unpack_intrinsic = bd.unpack_rows * UNPACK_INTRINSIC_COLS;
    let mulmod_intrinsic = bd.mulmod_total() * MULMOD_INTRINSIC_COLS;
    let mulmod_mismatch  = bd.mulmod_total() * MULMOD_MISMATCH_COLS;
    let bfly_intrinsic   = bd.bfly_total() * BFLY_INTRINSIC_COLS;
    let bfly_mismatch    = bd.bfly_total() * BFLY_MISMATCH_COLS;
    let selector_cells   = total_logical * SELECTOR_COLS;
    // 나머지 컬럼은 미사용 패딩 (각 게이트가 width=48 을 다 못 채움).
    let unused_cells = total_logical * W
        - (unpack_intrinsic + mulmod_intrinsic + mulmod_mismatch
            + bfly_intrinsic + bfly_mismatch + selector_cells);

    let intrinsic_total = unpack_intrinsic + mulmod_intrinsic + bfly_intrinsic;
    let mismatch_total  = mulmod_mismatch + bfly_mismatch;

    println!("── Counterfactual cell decomposition (논문 핵심) ──");
    println!("각 게이트의 컬럼을 '산술 본질' vs '필드 미스매치 비트분해' 로 분리:");
    println!();
    println!("  Intrinsic (SWIFFT 본질 산술) :");
    println!("    UNPACK byte→2bit×4  : {:>10} cells", unpack_intrinsic);
    println!("    MULMOD u,f,prod,k,r : {:>10} cells", mulmod_intrinsic);
    println!("    BFLY   a,b,w,...,fhi: {:>10} cells", bfly_intrinsic);
    println!("    ─────────────────────  ──────────");
    println!("    subtotal            : {:>10} cells ({:>5.1}%)",
             intrinsic_total, 100.0 * intrinsic_total as f64 / total_cells as f64);
    println!();
    println!("  Mismatch (q=257 ≠ BabyBear 비트분해 강제):");
    println!("    MULMOD r_low+r_top+k: {:>10} cells", mulmod_mismatch);
    println!("    BFLY   v/k1/lo/hi 분해: {:>10} cells", bfly_mismatch);
    println!("    ─────────────────────  ──────────");
    println!("    subtotal            : {:>10} cells ({:>5.1}%)",
             mismatch_total, 100.0 * mismatch_total as f64 / total_cells as f64);
    println!();
    println!("  Selector (unified AIR soundness):");
    println!("    su, sm, sb          : {:>10} cells ({:>5.1}%)",
             selector_cells, 100.0 * selector_cells as f64 / total_cells as f64);
    println!();
    println!("  Unused / row-padding within width:");
    println!("    (각 게이트가 width=48 을 다 채우지 못함):");
    println!("                        : {:>10} cells ({:>5.1}%)",
             unused_cells, 100.0 * unused_cells as f64 / total_cells as f64);
    println!("  Pow2 row padding (NOP rows):");
    println!("                        : {:>10} cells ({:>5.1}%)",
             padding_cells, 100.0 * padding_cells as f64 / total_cells as f64);
    println!();

    // ── 반사실 추정: 만약 모듈러스가 BabyBear 호환이었다면? ──
    //
    // 가정: q 가 BabyBear 내부에서 자연스럽게 다뤄지면 MULMOD/BFLY 의 비트
    // 분해 컬럼이 불필요 (Poseidon2 처럼 산술 본질만 남음). 이때 width 는
    // 줄어들고 selector 3 컬럼은 여전히 필요. 가장 큰 게이트(BFLY)의 본질
    // 컬럼 10 을 width 로 가정한 보수적 추정.
    let counterfactual_width = BFLY_INTRINSIC_COLS + SELECTOR_COLS; // 10 + 3 = 13
    let counterfactual_rows = total_logical; // 행 수는 동일 (산술 구조 불변)
    // counterfactual_rows 는 padding 전이고, next_pow2 padding 은 width 와
    // 무관하게 동일하게 적용된다 (행 단위 padding 이므로).
    let counterfactual_padded_rows = counterfactual_rows.next_power_of_two();
    let counterfactual_cells = counterfactual_padded_rows * counterfactual_width;

    println!("── Counterfactual: BabyBear-friendly modulus 가정 시 ──");
    println!("(가정: q 가 BabyBear 내부에서 자연스럽다면 비트분해 컬럼 제거 가능)");
    println!("  추정 width  : {counterfactual_width} (BFLY 본질 {BFLY_INTRINSIC_COLS} + selector {SELECTOR_COLS})");
    println!("  추정 rows   : {counterfactual_padded_rows} (구조 동일)");
    println!("  추정 cells  : {counterfactual_cells}");
    println!("  현재 cells  : {total_cells}");
    println!("  추정 절감률 : {:.1}× ({:.1}% reduction)",
             total_cells as f64 / counterfactual_cells as f64,
             100.0 * (1.0 - counterfactual_cells as f64 / total_cells as f64));
    println!();
    println!("주의: 이 반사실은 '필드 미스매치가 제거된 *동일 알고리즘*'의 상한선.");
    println!("       실제 BabyBear 친화 격자 해시는 알고리즘 자체도 재설계되어");
    println!("       추가 절감이 가능할 수 있다. 본 추정은 보수적 lower bound.");

    // JSON 부분 갱신 (논문/대시보드에서 활용)
    write_breakdown_json(bd, padded_rows, total_cells, counterfactual_cells);
}

fn write_breakdown_json(
    bd: &GateBreakdown,
    padded_rows: usize,
    total_cells: usize,
    counterfactual_cells: usize,
) {
    let path = "swifft_cost_breakdown.json";
    // 단순 JSON 직접 작성 (serde 없이).
    let json = format!(
        "{{\n\
         \"unpack_rows\": {},\n\
         \"mulmod_rows_total\": {},\n\
         \"mulmod_rows_psi_twist\": {},\n\
         \"mulmod_rows_pointwise\": {},\n\
         \"mulmod_rows_ninv\": {},\n\
         \"mulmod_rows_psi_inv\": {},\n\
         \"bfly_rows_total\": {},\n\
         \"bfly_rows_forward\": {},\n\
         \"bfly_rows_inverse\": {},\n\
         \"total_logical_rows\": {},\n\
         \"padded_rows\": {},\n\
         \"width\": {},\n\
         \"total_cells\": {},\n\
         \"counterfactual_cells_no_mismatch\": {},\n\
         \"counterfactual_reduction_factor\": {:.3},\n\
         \"_note\": \"counterfactual = if modulus were BabyBear-friendly, eliminating bit-decomposition columns. Conservative lower bound.\"\n\
         }}\n",
        bd.unpack_rows,
        bd.mulmod_total(),
        bd.mulmod_rows_psi_twist,
        bd.mulmod_rows_pointwise,
        bd.mulmod_rows_ninv,
        bd.mulmod_rows_psi_inv,
        bd.bfly_total(),
        bd.bfly_rows_forward,
        bd.bfly_rows_inverse,
        bd.total_rows(),
        padded_rows,
        W,
        total_cells,
        counterfactual_cells,
        total_cells as f64 / counterfactual_cells as f64,
    );
    if let Err(e) = fs::write(path, json) {
        eprintln!("⚠️  Failed to write {path}: {e}");
    } else {
        println!("\n💾 Wrote cost breakdown to {path}");
    }
}

fn main() {
    // dhat 힙 프로파일러 시작 (이 시점부터 모든 힙 할당 추적).
    let _profiler = dhat::Profiler::new_heap();

    println!("SWIFFT full trace + verified unified AIR prove/verify (AIR-1)\n");

    let data = vec![0u8; 1024];
    let mut keys = [[0i32; N]; M];
    for i in 0..M {
        for j in 0..N {
            keys[i][j] = ((i + j) % (ntt::Q as usize)) as i32;
        }
    }

    // ── self-check ──
    {
        let mut probe = [0u8; 256];
        for (idx, b) in probe.iter_mut().enumerate() {
            *b = ((idx * 7 + 13) & 0xFF) as u8;
        }
        let mut scratch: Vec<BabyBear> = Vec::new();
        let mut scratch_bd = GateBreakdown::default();
        let got = swifft_block_traced(&mut scratch, &probe, &keys, &mut scratch_bd);

        let naive = SwifftHasherNaive {
            keys: core::array::from_fn(|i| {
                let mut p = SwifftPolyNaive::new();
                for j in 0..N {
                    p.coeffs[j] = keys[i][j].rem_euclid(ntt::Q) as u16;
                }
                p
            }),
        };
        let mut polys = [SwifftPolyNaive::new(); M];
        for i in 0..M {
            let c = &probe[i * 16..(i + 1) * 16];
            for j in 0..16 {
                let byte = c[j] as i32;
                for b in 0..4 {
                    polys[i].coeffs[j * 4 + b] = ((byte >> (b * 2)) & 3) as u16;
                }
            }
        }
        let expect = naive.compress(&polys).coeffs;
        let got_u16: [u16; N] = core::array::from_fn(|j| got[j].rem_euclid(ntt::Q) as u16);
        assert_eq!(
            got_u16, expect,
            "trace witness output != naive oracle (trace generation is WRONG)"
        );
        println!("[self-check] trace witness == SwifftHasherNaive oracle: OK");
    }

    // ── 실제 trace 생성 (게이트별 카운트 활성화) ──
    let mut breakdown = GateBreakdown::default();
    let trace = generate_swifft_trace(&data, &keys, &mut breakdown);
    let width = trace.width();
    let height = trace.height();
    let total_cells = width * height;
    let num_blocks = data.len() / 256;

    println!("\nTrace generated for {} B ({} blocks).", data.len(), num_blocks);
    println!("Dimensions: {height} rows x {width} cols");
    println!("Trace Size (cells): {total_cells}");
    println!("(Key NTT excluded from witness — keys are public constants.)");

    // ── [추가] 게이트별 비용 분해 출력 ──
    print_cost_breakdown(&breakdown, num_blocks, height);

    // ── prove → (peak 메모리 측정) → verify ──
    {
        let config = make_config();
        let air = SwifftUnifiedAir;
        println!("\nProving full SWIFFT trace under the unified AIR...");

        let before = dhat::HeapStats::get();
        let proof = prove::<MyConfig, _>(&config, &air, trace, &[]);
        let after_prove = dhat::HeapStats::get();
        black_box(&proof);

        let verify_ok = verify(&config, &air, &proof, &[]).is_ok();

        let peak_bytes = after_prove.max_bytes;
        let peak_kb = peak_bytes as f64 / 1024.0;
        let prove_alloc_delta =
            after_prove.total_bytes.saturating_sub(before.total_bytes);

        if verify_ok {
            println!(
                "[AIR-1] full SWIFFT prove + verify -> OK\n\
                 This trace is now enforced by verified AIR constraints\n\
                 (not a dummy). Honest trace size: {total_cells} cells\n\
                 ({height} rows x {width} cols), degree 3, log_blowup {SWIFFT_LOG_BLOWUP}."
            );
        } else {
            println!("[AIR-1] full SWIFFT verify FAILED");
            std::process::exit(1);
        }

        println!(
            "Peak heap (trace+prove workflow): {peak_bytes} bytes ({peak_kb:.1} KB)"
        );
        println!("Prove-section cumulative alloc:   {prove_alloc_delta} bytes");

        // ── memory_results.json 부분 갱신 (SWIFFT 키 + config 메타) ──
        let path = "memory_results.json";
        let mut map = match fs::read_to_string(path) {
            Ok(s) => parse_simple_json(&s),
            Err(_) => std::collections::BTreeMap::new(),
        };
        let kb = peak_kb.round() as i64;
        for key in ["SWIFFT-Naive", "SWIFFT-Scalar", "SWIFFT-AVX2"] {
            map.insert(key.to_string(), JVal::Num(kb));
        }
        map.insert("_swifft_log_blowup".to_string(), JVal::Num(SWIFFT_LOG_BLOWUP as i64));
        map.insert("_swifft_height".to_string(), JVal::Num(height as i64));
        map.insert("_swifft_cells".to_string(), JVal::Num(total_cells as i64));
        map.insert(
            "_metric".to_string(),
            JVal::Str(
                "peak heap KB of full trace-gen + STARK-prove; per-circuit minimal config (see _swifft_log_blowup vs others' blowup=1)".to_string(),
            ),
        );
        fs::write(path, dump_simple_json(&map)).expect("write memory_results.json");
        println!(
            "\n💾 Updated {path} [SWIFFT-* = {kb} KB, log_blowup={SWIFFT_LOG_BLOWUP}, height={height}]"
        );
    }

    println!(
        "\nNote: SWIFFT 메모리는 log_blowup=2 (degree-3 제약 필수) + height\n\
         {height}(2^15) 기준. SHA/Keccak/Poseidon2 는 blowup=1 + 2^14.\n\
         절대 비교 금지 — config 보정 후 상대 해석만 유효."
    );
}

// ── serde 없는 최소 JSON (mem_prove_* 와 동일 구현, 부분 갱신 호환) ──
#[derive(Clone)]
enum JVal {
    Num(i64),
    Str(String),
}

fn parse_simple_json(s: &str) -> std::collections::BTreeMap<String, JVal> {
    let mut m = std::collections::BTreeMap::new();
    let body = s.trim().trim_start_matches('{').trim_end_matches('}');
    for part in body.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(colon) = part.find(':') {
            let raw_k = part[..colon].trim().trim_matches('"').to_string();
            let raw_v = part[colon + 1..].trim();
            if raw_v.starts_with('"') {
                m.insert(raw_k, JVal::Str(raw_v.trim_matches('"').to_string()));
            } else if let Ok(n) = raw_v.parse::<i64>() {
                m.insert(raw_k, JVal::Num(n));
            }
        }
    }
    m
}

fn dump_simple_json(m: &std::collections::BTreeMap<String, JVal>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in m {
        let vs = match v {
            JVal::Num(n) => n.to_string(),
            JVal::Str(s) => format!("\"{}\"", s.replace('"', "\\\"")),
        };
        parts.push(format!("  \"{}\": {}", k, vs));
    }
    format!("{{\n{}\n}}", parts.join(",\n"))
}