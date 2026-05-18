// src/bin/mem_prove_poseidon2.rs
//
// 목적: Poseidon2 (BabyBear w16) AIR 의 STARK 증명 생성 시 peak 힙 메모리 측정.
//
// mem_prove_sha256.rs / mem_prove_keccak.rs 의 검증된 패턴을 복제.
//   - config(make_config): SHA/Keccak 버전과 100% 동일 (알고리즘 무관).
//   - air/trace: Poseidon2Air::new(constants) + air.generate_trace_rows(n,0)
//     (trace_poseidon2.rs 에서 검증된 패턴).
//   - 워크로드 통일: Poseidon2 는 permutation 당 1행 → height = num_perm.
//     SHA/Keccak 과 동일 2^14 = 16384 행 → num_perm = 16384.
//
// 측정값 정의(SHA/Keccak 과 동일): "trace 생성 + 증명 생성 전체
// 워크플로우의 peak 힙(max_bytes)". dhat peak 리셋 불가 → 정직하게 라벨링.

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_S_BOX_DEGREE,
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, StarkConfig};

use rand::rngs::SmallRng;
use rand::SeedableRng;

use std::fs;
use std::hint::black_box;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// trace_poseidon2.rs 와 동일한 BabyBear w16 표준 파라미터 (소스 확정값)
const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 1;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

type F = BabyBear;
type LL = GenericPoseidon2LinearLayersBabyBear;
type MyAir = Poseidon2Air<
    F,
    LL,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type MyMmcs = MerkleTreeMmcs<F, u8, FieldHash, MyCompress, 2, 32>;
type MyDft = Radix2Bowers;
type MyPcs = TwoAdicFriPcs<F, MyDft, MyMmcs, MyMmcs>;
type ByteChallenger = HashChallenger<u8, ByteHash, 32>;
type MyChallenger = SerializingChallenger32<F, ByteChallenger>;
type MyConfig = StarkConfig<MyPcs, F, MyChallenger>;

// mem_prove_sha256.rs / mem_prove_keccak.rs 와 동일한 검증된 config
fn make_config() -> MyConfig {
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(ByteHash {});
    let mmcs = MyMmcs::new(field_hash, compress, 0);
    let dft = MyDft::default();
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: mmcs.clone(),
    };
    let pcs = MyPcs::new(dft, mmcs, fri_params);
    let byte_challenger = ByteChallenger::new(vec![], ByteHash {});
    let challenger = MyChallenger::new(byte_challenger);
    MyConfig::new(pcs, challenger)
}

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    println!("=== Poseidon2 (BabyBear w16) STARK Prove — Peak Memory ===\n");

    let config = make_config();

    // trace_poseidon2.rs 와 동일: 공식 예제 방식의 RNG/constants
    let mut rng = SmallRng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let air: MyAir = Poseidon2Air::new(constants);

    // 워크로드 통일: perm당 1행 → num_perm = 16384 = 2^14 (SHA/Keccak 과 동일)
    let num_perms = 1usize << 14;
    let trace = air.generate_trace_rows(num_perms, 0);

    let width = trace.width();
    let height = trace.height();
    let trace_cells = width * height;
    println!("num_perms={num_perms}");
    println!("Trace: {height} rows x {width} cols = {trace_cells} cells");

    let before = dhat::HeapStats::get();
    let proof = prove(&config, &air, trace, &vec![]);
    black_box(&proof);
    let after = dhat::HeapStats::get();

    let peak_bytes = after.max_bytes;
    let peak_kb = peak_bytes as f64 / 1024.0;
    let prove_alloc_delta = after.total_bytes.saturating_sub(before.total_bytes);

    println!("Peak heap (trace+prove workflow): {peak_bytes} bytes ({peak_kb:.1} KB)");
    println!("Prove-section cumulative alloc:   {prove_alloc_delta} bytes");

    // ── memory_results.json 부분 갱신 (Poseidon2 키만) ──
    let key = "Poseidon2";
    let path = "memory_results.json";

    let mut map = match fs::read_to_string(path) {
        Ok(s) => parse_simple_json(&s),
        Err(_) => std::collections::BTreeMap::new(),
    };
    map.insert(key.to_string(), JVal::Num(peak_kb.round() as i64));
    map.insert(
        "_metric".to_string(),
        JVal::Str(
            "peak heap KB of full trace-generation + STARK-proving workflow".to_string(),
        ),
    );
    fs::write(path, dump_simple_json(&map)).expect("Unable to write memory_results.json");
    println!("\n💾 Updated {path} [\"{key}\" = {} KB]", peak_kb.round() as i64);
}

// ── serde 없는 최소 JSON (mem_prove_sha256/keccak 과 동일 구현) ──
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