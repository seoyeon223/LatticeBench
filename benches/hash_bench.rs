use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use lattice_bench::{SwifftHasher, SwifftPoly, SWIFFT_M, SWIFFT_DEGREE};
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;
use pprof::criterion::{Output, PProfProfiler};
use sha2::{Sha256, Digest}; 
use p3_baby_bear::BabyBear;
use p3_symmetric::Permutation;

fn hash_comparison_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash Comparison (Raw Bytes)");
    
    let raw_data = vec![0u8; 1024];
    
    // 처리량(Throughput) 측정 설정: 전체 그룹에 일괄 적용됩니다.
    group.throughput(criterion::Throughput::Bytes(raw_data.len() as u64));
    
    // 해시 인스턴스 초기화
    let swifft_hasher = SwifftHasher::new();
    let keccak_hasher = Keccak256Hash {}; 

    // 1. SWIFFT
    // 대시보드 인식명에 맞춰 "SWIFFT (Lattice)" -> "SWIFFT" 로 변경
    group.bench_function("SWIFFT", |b| {
        b.iter_batched(
            || {
                let mut swifft_inputs = [SwifftPoly::new(); SWIFFT_M];
                for i in 0..SWIFFT_M {
                    for j in 0..SWIFFT_DEGREE {
                        swifft_inputs[i].coeffs[j] = raw_data[i * SWIFFT_DEGREE + j] as u16;
                    }
                }
                swifft_inputs
            },
            |prepared_inputs| {
                let result = swifft_hasher.compress(black_box(&prepared_inputs));
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // 2. Keccak
    // "Keccak-256" -> "Keccak" 으로 변경
    group.bench_function("Keccak", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            let result = keccak_hasher.hash_iter(bytes.iter().cloned());
            black_box(result)
        })
    });

    // 3. SHA-256
    // "SHA-256 (Native)" -> "SHA-256" 으로 변경 (이 부분이 0으로 나오는 핵심 원인이었습니다)
    group.bench_function("SHA-256", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let result = hasher.finalize();
            black_box(result)
        })
    });

    // 4. Poseidon
    // "Poseidon2 (Permutation, BabyBear)" -> "Poseidon" 으로 변경
    group.bench_function("Poseidon", |b| {
        let poseidon2 = p3_baby_bear::default_babybear_poseidon2_16();

        b.iter_batched(
            || {
                let mut state = [BabyBear::new(0); 16];
                for i in 0..16 {
                    state[i] = BabyBear::new((i as u32) % 257);
                }
                state
            },
            |mut state| {
                poseidon2.permute_mut(&mut state);
                black_box(state)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = hash_comparison_bench
);
criterion_main!(benches);