//src/bin/prove_bench.rs


use p3_baby_bear::BabyBear;
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_uni_stark::{StarkConfig, prove};
use p3_matrix::Matrix; // 🟢 [추가됨] 행렬의 width()와 height()를 구하기 위해 필수!
use std::time::Instant;
use std::fs;

// 분리했던 SHA-256 모듈 가져오기
use lattice_bench::sha256::{Sha256BitwiseAir, generate_sha256_trace};

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

fn main() {
    println!("⚙️ Setting up STARK Configuration...\n");

    let byte_hash = ByteHash {};
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

    // 4. Challenger 인스턴스 생성
    let byte_challenger = ByteChallenger::new(vec![], ByteHash {});
    let challenger = MyChallenger::new(byte_challenger);

    // 5. StarkConfig 조립
    let config = MyConfig::new(pcs, challenger);

    println!("✅ STARK Config successfully initialized!");
    println!("Generating SHA-256 Trace (16,384 rows)...");

    let air = Sha256BitwiseAir {};
    let trace = generate_sha256_trace::<F>();

    // 🟢 [추가됨] 증명을 생성하기 전에(trace가 소비되기 전에) 크기를 미리 계산하고 출력!
    let width = trace.width();
    let height = trace.height();
    let trace_size = width * height;
    
    println!("📊 Dimensions: {} rows × {} columns", height, width);
    println!("Trace Size: {}", trace_size); // 대시보드의 정규식이 이 줄을 파싱합니다.

    println!("🚀 Starting STARK Proof Generation...");
    let start = Instant::now();

    // 6. 증명 생성!
    let _proof = prove::<MyConfig, _>(&config, &air, trace, &[]); // _proof로 경고(Warning) 억제

    let proving_time = start.elapsed().as_micros() as f64;
    println!("🎉 Proof generated successfully!");
    println!("⏱️ Proving Time: {:.2} µs", proving_time);

    // 증명 소요 시간을 JSON으로 저장 (선택 사항)
    let json_output = format!(r#"{{
  "SHA-256_Proving_us": {:.2}
}}"#, proving_time);

    fs::write("prove_results.json", json_output).expect("Unable to write JSON");
    println!("💾 Benchmark results saved to prove_results.json");
}