// src/bin/mem_prove_sha256.rs
//
// 목적: SHA-256(bitwise) AIR 의 STARK 증명 생성 시 peak 힙 메모리 측정.
//
// 설계 결정 (dhat 0.3.3 의 본질적 제약에서 비롯):
//   - dhat::Profiler 는 프로그램당 1개, peak(max_bytes) 리셋 불가.
//   - #[global_allocator] 가 prove 경로 모든 할당을 추적 → proving TIME 이
//     크게 느려짐. 따라서 시간 측정(prove_bench.rs)과 메모리 측정은
//     반드시 *별도 바이너리* 로 분리한다. (한 바이너리에서 둘 다 재면 둘 다
//     부정확해진다.)
//   - prove 는 trace 를 LDE blowup(log_blowup=1 → 2x) + FRI 폴딩하므로
//     일반적으로 prove peak > trace 할당. 그래도 dhat 이 peak 를 리셋
//     못 하므로, 보고값의 정의는 정직하게:
//       "trace 생성 + 증명 생성 전체 워크플로우의 peak 힙 (max_bytes)".
//     이는 ZK 에서 실제 메모리 병목 단위와 일치하므로 실용적으로 유효.
//
// config 는 prove_bench.rs / trace_swifft.rs 에서 컴파일·동작 검증된
// 패턴을 그대로 사용 (커밋 64b3cc0 기준).

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, StarkConfig};

use std::fs;
use std::hint::black_box;

use lattice_bench::sha256::{generate_sha256_trace, Sha256BitwiseAir};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

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

// prove_bench.rs 와 동일한 검증된 config
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
    // dhat 힙 프로파일러 시작 (이 시점부터 모든 힙 할당 추적)
    let _profiler = dhat::Profiler::new_heap();

    println!("=== SHA-256 (bitwise) STARK Prove — Peak Memory ===\n");

    let config = make_config();
    let air = Sha256BitwiseAir;

    // prove_bench.rs 와 동일 워크로드: 2^14 = 16,384 행
    let num_rows = 1 << 14;
    let trace = generate_sha256_trace::<F>(num_rows);

    let width = trace.width();
    let height = trace.height();
    let trace_cells = width * height;
    println!("Trace: {height} rows x {width} cols = {trace_cells} cells");

    // ── prove 직전/직후 힙 통계 ──
    let before = dhat::HeapStats::get();
    let proof = prove(&config, &air, trace, &vec![]);
    black_box(&proof); // prove 결과가 최적화로 제거되지 않도록
    let after = dhat::HeapStats::get();

    // max_bytes = 전체 실행 중 peak (trace 생성 + prove 포함).
    // dhat 은 peak 리셋 불가하므로 정의를 정직하게 라벨링.
    let peak_bytes = after.max_bytes;
    let peak_kb = peak_bytes as f64 / 1024.0;

    // 참고용: prove 구간에서 새로 누적 할당된 바이트 (peak 아님)
    let prove_alloc_delta = after.total_bytes.saturating_sub(before.total_bytes);

    println!("Peak heap (trace+prove workflow): {peak_bytes} bytes ({peak_kb:.1} KB)");
    println!("Prove-section cumulative alloc:   {prove_alloc_delta} bytes");

    // ── memory_results.json 갱신 (대시보드 표준 키) ──
    // 기존 파일이 있으면 읽어서 SHA 항목만 갱신, 없으면 새로 생성.
    let key = "SHA-256-style bitwise circuit";
    let path = "memory_results.json";

    let mut map: std::collections::BTreeMap<String, serde_json_value::Value> =
        match fs::read_to_string(path) {
            Ok(s) => parse_simple_json(&s),
            Err(_) => std::collections::BTreeMap::new(),
        };
    // peak 를 KB 단위 정수로 저장 (대시보드 Memory (KB) 열과 일치)
    map.insert(
        key.to_string(),
        serde_json_value::Value::Num(peak_kb.round() as i64),
    );
    map.insert(
        "_metric".to_string(),
        serde_json_value::Value::Str(
            "peak heap KB of full trace-generation + STARK-proving workflow".to_string(),
        ),
    );

    fs::write(path, dump_simple_json(&map)).expect("Unable to write memory_results.json");
    println!("\n💾 Updated {path} [\"{key}\" = {} KB]", peak_kb.round() as i64);
}

// ──────────────────────────────────────────────────────────────────
// serde 의존성 없이 쓰는 최소 JSON 직렬화 (문자열/정수만, 평면 객체).
// 다른 mem_prove_* 바이너리가 같은 파일을 부분 갱신해도 깨지지 않도록
// 기존 키를 보존한다.
// ──────────────────────────────────────────────────────────────────
mod serde_json_value {
    #[derive(Clone)]
    pub enum Value {
        Num(i64),
        Str(String),
    }
}

fn parse_simple_json(
    s: &str,
) -> std::collections::BTreeMap<String, serde_json_value::Value> {
    use serde_json_value::Value;
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
                m.insert(
                    raw_k,
                    Value::Str(raw_v.trim_matches('"').to_string()),
                );
            } else if let Ok(n) = raw_v.parse::<i64>() {
                m.insert(raw_k, Value::Num(n));
            }
        }
    }
    m
}

fn dump_simple_json(
    m: &std::collections::BTreeMap<String, serde_json_value::Value>,
) -> String {
    use serde_json_value::Value;
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in m {
        let vs = match v {
            Value::Num(n) => n.to_string(),
            Value::Str(s) => format!("\"{}\"", s.replace('"', "\\\"")),
        };
        parts.push(format!("  \"{}\": {}", k, vs));
    }
    format!("{{\n{}\n}}", parts.join(",\n"))
}