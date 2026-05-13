use p3_baby_bear::BabyBear;
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_uni_stark::{StarkConfig, prove};
use std::time::Instant;
use std::fs;

// 분리했던 SHA-256 모듈 가져오기
use lattice_bench::sha256::{Sha256BitwiseAir, generate_sha256_trace};

type F = BabyBear;

// 🟢 1. 바이트(u8)와 유한체(F)를 완벽히 호환시키는 Keccak 세팅
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type MyMmcs = MerkleTreeMmcs<F, u8, FieldHash, MyCompress, 2, 32>;
type MyDft = Radix2Bowers;
type MyPcs = TwoAdicFriPcs<F, MyDft, MyMmcs, MyMmcs>;

// 🟢 2. 바이트 기반 챌린저를 유한체용으로 감싸는 어댑터(SerializingChallenger32) 적용
type ByteChallenger = HashChallenger<u8, ByteHash, 32>;
type MyChallenger = SerializingChallenger32<F, ByteChallenger>;
type MyConfig = StarkConfig<MyPcs, F, MyChallenger>;

fn main() {
    println!("⚙️ Setting up STARK Configuration...\n");

    // 1. Hash & MMCS 인스턴스 생성
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(ByteHash {});
    let mmcs = MyMmcs::new(field_hash, compress, 32);

    // 2. DFT 세팅
    let dft = MyDft::default();

    // 3. FRI (PCS) 세팅 (🔥 누락되었던 mmcs 추가 복구 완료!)
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

    // 4. Challenger 인스턴스 생성 (바이트용 생성 -> 유한체 어댑터 씌우기)
    let byte_challenger = ByteChallenger::new(vec![], ByteHash {});
    let challenger = MyChallenger::new(byte_challenger);

    // 5. 대망의 StarkConfig 조립
    let config = MyConfig::new(pcs, challenger);

    println!("✅ STARK Config successfully initialized!");
    println!("Generating SHA-256 Trace (16,384 rows)...");

    let air = Sha256BitwiseAir {};
    let trace = generate_sha256_trace::<F>();

    println!("🚀 Starting STARK Proof Generation...");
    let start = Instant::now();

    // 6. 증명 생성!
    let proof = prove::<MyConfig, _>(&config, &air, trace, &[]);

    let proving_time = start.elapsed().as_micros() as f64;
    println!("🎉 Proof generated successfully!");
    println!("⏱️ Proving Time: {:.2} µs", proving_time);

    let json_output = format!(r#"{{
  "SHA-256_Proving_us": {:.2}
}}"#, proving_time);

    fs::write("prove_results.json", json_output).expect("Unable to write JSON");
    println!("💾 Benchmark results saved to prove_results.json");
}