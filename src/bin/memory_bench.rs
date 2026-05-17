use dhat::{Alloc, Profiler, HeapStats};
use p3_keccak::Keccak256Hash;
use p3_sha256::Sha256;
use p3_symmetric::CryptographicHasher;

use p3_baby_bear::{BabyBear, Poseidon2BabyBear}; 
use p3_symmetric::PaddingFreeSponge;

use std::fs::File;
use std::io::Write;
use std::collections::HashMap;
use std::hint::black_box;

// 🟢 고정된 시드의 난수를 생성하기 위해 StdRng 사용 (에러 완벽 해결)
use rand::SeedableRng;
use rand::rngs::StdRng;

use lattice_bench::{SwifftHasherNaive, SwifftPolyNaive};
use lattice_bench::swifft::SwifftHasherNTT;
use lattice_bench::swifft::simd::SwifftHasherSimd;

// 글로벌 할당자 등록
#[global_allocator]
static ALLOC: Alloc = Alloc;

fn bytes_to_naive_polys(chunk: &[u8]) -> [SwifftPolyNaive; 16] {
    let mut polys = [SwifftPolyNaive::new(); 16];
    for i in 0..16 {
        let poly_chunk = &chunk[i * 16..(i + 1) * 16];
        for j in 0..16 {
            let byte = poly_chunk[j];
            for b in 0..4 {
                polys[i].coeffs[j * 4 + b] = ((byte >> (b * 2)) & 0x03) as u16;
            }
        }
    }
    polys
}

fn main() {
    let _profiler = Profiler::new_heap();

    println!("Starting Memory Benchmark for Hash Algorithms...\n");

    let mut results = HashMap::new();
    let data = vec![0u8; 1024]; 

    // ----------------------------------------------------
    // 1. Keccak-256 측정
    // ----------------------------------------------------
    let _stats_before = HeapStats::get();
    {
        let keccak = Keccak256Hash {};
        black_box(keccak.hash_iter(black_box(&data).iter().cloned()));
    }
    let _stats_after = HeapStats::get();
    results.insert("Keccak", (_stats_after.total_bytes - _stats_before.total_bytes) as f64 / 1024.0);

    // ----------------------------------------------------
    // 2. SHA-256 측정
    // ----------------------------------------------------
    let _stats_before = HeapStats::get();
    {
        let sha256 = Sha256 {}; 
        black_box(sha256.hash_iter(black_box(&data).iter().cloned()));
    }
    let _stats_after = HeapStats::get();
    results.insert("SHA-256", (_stats_after.total_bytes - _stats_before.total_bytes) as f64 / 1024.0);

    // ----------------------------------------------------
    // 3. Poseidon2 측정
    // ----------------------------------------------------
    let _stats_before = HeapStats::get();
    {
        // 🟢 OS에 의존하지 않는 고정 시드 난수기 사용 (결정론적 벤치마크)
        let mut rng = StdRng::seed_from_u64(0);
        let poseidon_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);
        let hasher = PaddingFreeSponge::<_, 16, 8, 4>::new(poseidon_perm);
        
        let data_bear = vec![BabyBear::default(); 256]; 
        black_box(hasher.hash_iter(black_box(&data_bear).iter().cloned()));
    }
    let _stats_after = HeapStats::get();
    results.insert("Poseidon", (_stats_after.total_bytes - _stats_before.total_bytes) as f64 / 1024.0);

    // ----------------------------------------------------
    // 🟢 공통 키 생성 (중괄호 바깥으로 완전히 빼서 에러 해결!)
    // ----------------------------------------------------
    let mut dummy_keys_i32 = [[0i32; 64]; 16];
    for i in 0..16 {
        for j in 0..64 { dummy_keys_i32[i][j] = ((i + j) % 257) as i32; }
    }

    // ----------------------------------------------------
    // 4. SWIFFT (Naive)
    // ----------------------------------------------------
    let _stats_before = HeapStats::get();
    {
        let swifft_naive = SwifftHasherNaive::new();
        for chunk in data.chunks_exact(256) {
            let polys = bytes_to_naive_polys(chunk);
            black_box(swifft_naive.compress(black_box(&polys)));
        }
    }
    let _stats_after = HeapStats::get();
    results.insert("SWIFFT-Naive", (_stats_after.total_bytes - _stats_before.total_bytes) as f64 / 1024.0);

    // ----------------------------------------------------
    // 5. SWIFFT (Scalar/NTT)
    // ----------------------------------------------------
    let _stats_before = HeapStats::get();
    {
        let swifft_scalar = SwifftHasherNTT::new(&dummy_keys_i32);
        for chunk in data.chunks_exact(256) {
            black_box(swifft_scalar.hash(black_box(chunk)));
        }
    }
    let _stats_after = HeapStats::get();
    results.insert("SWIFFT-Scalar", (_stats_after.total_bytes - _stats_before.total_bytes) as f64 / 1024.0);

    // ----------------------------------------------------
    // 6. SWIFFT (AVX2/SIMD)
    // ----------------------------------------------------
    let _stats_before = HeapStats::get();
    {
        let swifft_simd = SwifftHasherSimd::new(&dummy_keys_i32);
        for chunk in data.chunks_exact(256) {
            black_box(swifft_simd.hash(black_box(chunk)));
        }
    }
    let _stats_after = HeapStats::get();
    results.insert("SWIFFT-AVX2", (_stats_after.total_bytes - _stats_before.total_bytes) as f64 / 1024.0);

    // ----------------------------------------------------
    // JSON 저장
    // ----------------------------------------------------
    let json_output = format!(
        "{{\n  \"Keccak\": {:.2},\n  \"SHA-256\": {:.2},\n  \"Poseidon\": {:.2},\n  \"SWIFFT-Naive\": {:.2},\n  \"SWIFFT-Scalar\": {:.2},\n  \"SWIFFT-AVX2\": {:.2}\n}}",
        results.get("Keccak").unwrap_or(&0.0),
        results.get("SHA-256").unwrap_or(&0.0),
        results.get("Poseidon").unwrap_or(&0.0),
        results.get("SWIFFT-Naive").unwrap_or(&0.0),
        results.get("SWIFFT-Scalar").unwrap_or(&0.0),
        results.get("SWIFFT-AVX2").unwrap_or(&0.0)
    );

    let mut file = File::create("memory_results.json").expect("Failed to create memory_results.json");
    file.write_all(json_output.as_bytes()).expect("Failed to write to memory_results.json");

    println!("🎉 Benchmark finished successfully.");
    println!("💾 Exported memory results to 'memory_results.json':\n{}", json_output);
}