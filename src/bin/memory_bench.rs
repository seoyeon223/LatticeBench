use dhat::{Alloc, Profiler, HeapStats};
use p3_keccak::Keccak256Hash;
use p3_sha256::Sha256;
use p3_symmetric::CryptographicHasher;

use p3_baby_bear::{BabyBear, Poseidon2BabyBear}; 
use p3_symmetric::{PaddingFreeSponge};
use lattice_bench::{SwifftHasher, SwifftPoly};

use std::fs::File;
use std::io::Write;
use std::collections::HashMap;

// 글로벌 할당자 등록
#[global_allocator]
static ALLOC: Alloc = Alloc;

fn main() {
    // 힙 프로파일링 시작 (dhat-heap.json 자동 생성)
    let _profiler = Profiler::new_heap();

    println!("Starting Memory Benchmark for Hash Algorithms...\n");

    // 결과를 저장할 해시맵
    let mut results = HashMap::new();

    // ----------------------------------------------------
    // 1. Keccak-256 측정 (바이트 단위)
    // ----------------------------------------------------
    let stats_before = HeapStats::get();
    {
        let keccak = Keccak256Hash {};
        let data = vec![0u8; 1024]; 
        let _hash = keccak.hash_iter(data.iter().cloned());
    }
    let stats_after = HeapStats::get();
    let keccak_mem_kb = (stats_after.total_bytes - stats_before.total_bytes) as f64 / 1024.0;
    results.insert("Keccak", keccak_mem_kb);

    // ----------------------------------------------------
    // 2. SHA-256 측정 (바이트 단위)
    // ----------------------------------------------------
    let stats_before = HeapStats::get();
    {
        let sha256 = Sha256 {}; 
        let data = vec![0u8; 1024]; 
        let _hash = sha256.hash_iter(data.iter().cloned());
    }
    let stats_after = HeapStats::get();
    let sha256_mem_kb = (stats_after.total_bytes - stats_before.total_bytes) as f64 / 1024.0;
    results.insert("SHA-256", sha256_mem_kb);

    // ----------------------------------------------------
    // 3. Poseidon2 측정 (유한체 Field 단위)
    // ----------------------------------------------------
    let stats_before = HeapStats::get();
    {
        let mut rng = rand::rng(); 
        let poseidon_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);
        let hasher = PaddingFreeSponge::<_, 16, 8, 4>::new(poseidon_perm);
        
        let data = vec![BabyBear::default(); 256]; 
        let _hash = hasher.hash_iter(data.iter().cloned());
    }
    let stats_after = HeapStats::get();
    let poseidon_mem_kb = (stats_after.total_bytes - stats_before.total_bytes) as f64 / 1024.0;
    results.insert("Poseidon", poseidon_mem_kb);

    // ----------------------------------------------------
    // 4. SWIFFT 측정 (격자 다항식 단위)
    // ----------------------------------------------------
    let stats_before = HeapStats::get();
    {
        let swifft = SwifftHasher::new();
        let inputs = [SwifftPoly::new(); 16];
        let _res = swifft.compress(&inputs);
    }
    let stats_after = HeapStats::get();
    let swifft_mem_kb = (stats_after.total_bytes - stats_before.total_bytes) as f64 / 1024.0;
    results.insert("SWIFFT", swifft_mem_kb);

    // ----------------------------------------------------
    // JSON 파일로 내보내기 (memory_results.json)
    // ----------------------------------------------------
    let json_output = format!(
        "{{\n  \"SHA-256\": {:.2},\n  \"Keccak\": {:.2},\n  \"Poseidon\": {:.2},\n  \"SWIFFT\": {:.2}\n}}",
        results["SHA-256"], results["Keccak"], results["Poseidon"], results["SWIFFT"]
    );

    let mut file = File::create("memory_results.json").expect("Failed to create memory_results.json");
    file.write_all(json_output.as_bytes()).expect("Failed to write to memory_results.json");

    println!("Benchmark finished successfully.");
    println!("Exported memory results to 'memory_results.json':\n{}", json_output);
}