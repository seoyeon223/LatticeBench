use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2Bowers;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove};
use std::fs;
use std::time::Instant;

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
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let mmcs = MyMmcs::new(field_hash, compress, 0); // ← cap_height = 0 추가

    let dft = MyDft::default();

    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,                 // 원본 코드에 있던 필드
        num_queries: 100,
        commit_proof_of_work_bits: 0,     // 분리된 PoW 필드 1
        query_proof_of_work_bits: 0,      // 분리된 PoW 필드 2
        mmcs: mmcs.clone(),
    };
    

    let pcs = MyPcs::new(dft, mmcs, fri_params);

    let byte_challenger = ByteChallenger::new(vec![], ByteHash {});
    let challenger = MyChallenger::new(byte_challenger);

    let config = MyConfig::new(pcs, challenger);

    println!("✅ STARK Config initialized!");

    // 2^14 = 16,384 행
    let num_rows = 1 << 14;
    println!("Generating trace ({num_rows} rows)...");

    let air = Sha256BitwiseAir;
    let trace = generate_sha256_trace::<F>(num_rows);

    let width = trace.width();
    let height = trace.height();
    let trace_size = width * height;

    println!("📊 Dimensions: {height} rows × {width} columns");
    println!("Trace Size: {trace_size}");

    println!("🚀 Starting STARK Proof Generation...");
    let start = Instant::now();

    let _proof = prove(&config, &air, trace, &vec![]);

    let proving_time = start.elapsed().as_micros() as f64;
    println!("🎉 Proof generated!");
    println!("⏱️ Proving Time: {proving_time:.2} µs");

    let json_output = format!("{{\n  \"SHA-256_Proving_us\": {proving_time:.2}\n}}");
    fs::write("prove_results.json", json_output).expect("Unable to write JSON");
    println!("💾 Saved to prove_results.json");
}