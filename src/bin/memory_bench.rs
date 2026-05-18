// src/bin/memory_bench.rs
//
// 목적: "해시 1회의 추가 힙 할당량" 을 알고리즘 간 *공정하게* 비교.
//
// 이전 버전의 문제
//   - Poseidon 구간 안에서만 rng/perm/입력 Vec 을 생성해 측정에 포함 →
//     해시 비용이 아니라 셋업 할당이 잡혀 Poseidon 만 튀었다.
//   - SWIFFT 는 키를 구간 밖에서 만들고 해시가 zero-alloc 이라 0,
//     Keccak/SHA 도 스택 처리라 0 → "0 vs 1.55" 는 불공정 비교였다.
//   - data 1024B 를 SWIFFT 는 4청크(256B×4) 처리, Keccak/SHA 는 1024B 1회로
//     처리량 자체가 달랐다.
//
// 공정성 원칙 (이번 버전)
//   1) 모든 셋업(키/퍼뮤테이션/입력 버퍼)은 측정 구간 *밖* 에서 미리 생성.
//   2) 입력 작업량 통일: 모두 256바이트(= SWIFFT 1블록 = 64 필드원소) 1회 해시.
//   3) 워밍업 1회로 once_cell 등 1회성 lazy 초기화를 측정에서 분리.
//   4) metric = total_bytes(after) - total_bytes(before)
//      = "그 구간에서 새로 할당된 바이트" → 라벨도 그대로 정직하게 표기.
//      (dhat total_bytes 는 단조 누적 카운터라 차이값이 '구간 새 할당'을
//       정확히 의미한다. peak 가 아니라 per-hash 추가 할당량을 잰다.)
//   5) 입력/출력 모두 black_box 로 최적화 제거 유지.
//
// 해석: SWIFFT/Keccak/SHA 가 0(또는 0에 근접)으로 나오는 것은 버그가 아니라
//       "해시 실행 중 힙을 쓰지 않는다(zero-allocation)" 는 사실이며, ZK
//       벤치마크 맥락에서는 오히려 강점이다.

use dhat::{Alloc, HeapStats, Profiler};
use p3_keccak::Keccak256Hash;
use p3_sha256::Sha256;
use p3_symmetric::CryptographicHasher;

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_symmetric::PaddingFreeSponge;

use std::collections::HashMap;
use std::fs::File;
use std::hint::black_box;
use std::io::Write;

use rand::rngs::StdRng;
use rand::SeedableRng;

use lattice_bench::swifft::simd::SwifftHasherSimd;
use lattice_bench::swifft::SwifftHasherNTT;
use lattice_bench::{SwifftHasherNaive, SwifftPolyNaive};

#[global_allocator]
static ALLOC: Alloc = Alloc;

/// 256바이트 → 16개 SwifftPolyNaive (2비트 계수 펼치기). 셋업 단계에서만 호출.
fn bytes_to_naive_polys(chunk: &[u8]) -> [SwifftPolyNaive; 16] {
    let mut polys = [SwifftPolyNaive::new(); 16];
    for i in 0..16 {
        let pc = &chunk[i * 16..(i + 1) * 16];
        for j in 0..16 {
            let byte = pc[j];
            for b in 0..4 {
                polys[i].coeffs[j * 4 + b] = ((byte >> (b * 2)) & 0x03) as u16;
            }
        }
    }
    polys
}

/// 측정 헬퍼: warmup() 으로 1회성 초기화를 끝낸 뒤, run() 1회의 추가 힙
/// 할당 바이트를 반환한다. 셋업은 이 함수 호출 *전* 에 이미 끝나 있어야 한다.
fn measure_alloc_bytes<W, R>(mut warmup: W, mut run: R) -> u64
where
    W: FnMut(),
    R: FnMut(),
{
    // 워밍업: lazy static / once_cell / 캐시 등 1회성 할당을 측정에서 분리.
    warmup();

    let before = HeapStats::get();
    run();
    let after = HeapStats::get();

    // total_bytes 는 단조 증가 누적 카운터 → 차이 = 이 구간에서 새로 할당된 양.
    after.total_bytes.saturating_sub(before.total_bytes)
}

fn main() {
    let _profiler = Profiler::new_heap();

    println!("Per-hash additional heap allocation (fair comparison)\n");

    // ── 공통 입력: 256바이트로 통일 (SWIFFT 1블록 = 64 필드원소) ──
    let data_256: Vec<u8> = (0..256u32).map(|i| (i & 0xFF) as u8).collect();

    let mut results: HashMap<&str, u64> = HashMap::new();

    // ──────────────────────────────────────────────────────────────
    // Keccak-256 : 셋업(해셔 생성)은 구간 밖. 256B 1회 해시만 측정.
    // ──────────────────────────────────────────────────────────────
    {
        let keccak = Keccak256Hash {};
        let bytes = measure_alloc_bytes(
            || {
                black_box(keccak.hash_iter(black_box(&data_256).iter().cloned()));
            },
            || {
                black_box(keccak.hash_iter(black_box(&data_256).iter().cloned()));
            },
        );
        results.insert("Keccak", bytes);
    }

    // ──────────────────────────────────────────────────────────────
    // SHA-256
    // ──────────────────────────────────────────────────────────────
    {
        let sha256 = Sha256 {};
        let bytes = measure_alloc_bytes(
            || {
                black_box(sha256.hash_iter(black_box(&data_256).iter().cloned()));
            },
            || {
                black_box(sha256.hash_iter(black_box(&data_256).iter().cloned()));
            },
        );
        results.insert("SHA-256", bytes);
    }

    // ──────────────────────────────────────────────────────────────
    // Poseidon2 : rng / 퍼뮤테이션 / 입력 Vec 은 *셋업* 으로 구간 밖에서 생성.
    //             측정 구간은 hash_iter 1회만.
    // ──────────────────────────────────────────────────────────────
    {
        // --- 셋업 (측정 제외) ---
        let mut rng = StdRng::seed_from_u64(0);
        let perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);
        let hasher = PaddingFreeSponge::<_, 16, 8, 4>::new(perm);
        // 입력도 256 원소로 통일 (다른 알고리즘의 256바이트와 동일 작업량 축).
        let input_bear = vec![BabyBear::default(); 256];

        // --- 측정 (해시 1회만) ---
        let bytes = measure_alloc_bytes(
            || {
                black_box(
                    hasher.hash_iter(black_box(&input_bear).iter().cloned()),
                );
            },
            || {
                black_box(
                    hasher.hash_iter(black_box(&input_bear).iter().cloned()),
                );
            },
        );
        results.insert("Poseidon", bytes);
    }

    // ── SWIFFT 공통 키 (셋업, 측정 제외) ──
    let mut dummy_keys_i32 = [[0i32; 64]; 16];
    for i in 0..16 {
        for j in 0..64 {
            dummy_keys_i32[i][j] = ((i + j) % 257) as i32;
        }
    }

    // ──────────────────────────────────────────────────────────────
    // SWIFFT (Naive) : 해셔/입력 polys 셋업은 구간 밖. compress 1회만 측정.
    // ──────────────────────────────────────────────────────────────
    {
        let swifft_naive = SwifftHasherNaive::new();
        let polys = bytes_to_naive_polys(&data_256); // 셋업
        let bytes = measure_alloc_bytes(
            || {
                black_box(swifft_naive.compress(black_box(&polys)));
            },
            || {
                black_box(swifft_naive.compress(black_box(&polys)));
            },
        );
        results.insert("SWIFFT-Naive", bytes);
    }

    // ──────────────────────────────────────────────────────────────
    // SWIFFT (Scalar/NTT) : new() 키 전처리는 셋업. hash 1회만 측정.
    // ──────────────────────────────────────────────────────────────
    {
        let swifft_scalar = SwifftHasherNTT::new(&dummy_keys_i32);
        let bytes = measure_alloc_bytes(
            || {
                black_box(swifft_scalar.hash(black_box(&data_256[..256])));
            },
            || {
                black_box(swifft_scalar.hash(black_box(&data_256[..256])));
            },
        );
        results.insert("SWIFFT-Scalar", bytes);
    }

    // ──────────────────────────────────────────────────────────────
    // SWIFFT (AVX2/SIMD) : new() 키 NTT 캐싱은 셋업. hash 1회만 측정.
    // ──────────────────────────────────────────────────────────────
    {
        let swifft_simd = SwifftHasherSimd::new(&dummy_keys_i32);
        let bytes = measure_alloc_bytes(
            || {
                black_box(swifft_simd.hash(black_box(&data_256[..256])));
            },
            || {
                black_box(swifft_simd.hash(black_box(&data_256[..256])));
            },
        );
        results.insert("SWIFFT-AVX2", bytes);
    }

    // ── 결과 출력 (바이트 단위, 정직한 라벨) ──
    let order = [
        "SWIFFT-Naive",
        "SWIFFT-Scalar",
        "SWIFFT-AVX2",
        "Keccak",
        "Poseidon",
        "SHA-256",
    ];
    println!("{:<16} {:>20}", "Algorithm", "Alloc bytes / hash");
    for name in order {
        println!("{:<16} {:>20}", name, results.get(name).copied().unwrap_or(0));
    }

    let g = |k: &str| results.get(k).copied().unwrap_or(0);
    let json_output = format!(
        "{{\n  \"_metric\": \"additional heap bytes allocated by a single hash call (setup excluded, 256-byte input)\",\n  \"Keccak\": {},\n  \"SHA-256\": {},\n  \"Poseidon\": {},\n  \"SWIFFT-Naive\": {},\n  \"SWIFFT-Scalar\": {},\n  \"SWIFFT-AVX2\": {}\n}}",
        g("Keccak"),
        g("SHA-256"),
        g("Poseidon"),
        g("SWIFFT-Naive"),
        g("SWIFFT-Scalar"),
        g("SWIFFT-AVX2"),
    );

    let mut file =
        File::create("memory_results.json").expect("Failed to create memory_results.json");
    file.write_all(json_output.as_bytes())
        .expect("Failed to write memory_results.json");

    println!("\nExported per-hash allocation (bytes) to 'memory_results.json':\n{}", json_output);
    println!(
        "\nNote: 0 (or near-0) for SWIFFT/Keccak/SHA means the hash performs no\n\
         heap allocation during execution (zero-allocation) — a strength in the\n\
         ZK benchmark context, not a measurement bug."
    );
}