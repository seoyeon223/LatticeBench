use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use lattice_bench::{SwifftHasher, SwifftPoly, SWIFFT_M, SWIFFT_DEGREE};
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;
use pprof::criterion::{Output, PProfProfiler};
use sha2::{Sha256, Digest}; // ✨ SHA-256 사용을 위한 필수 임포트
use p3_baby_bear::BabyBear;
use p3_symmetric::Permutation; // 순열 연산을 위한 트레이트


fn hash_comparison_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash Comparison (Raw Bytes)");
    
    let raw_data = vec![0u8; 1024];
    
    // 처리량(Throughput) 측정 설정
    group.throughput(criterion::Throughput::Bytes(raw_data.len() as u64));
    
    // 해시 인스턴스 초기화
    let swifft_hasher = SwifftHasher::new();
    let keccak_hasher = Keccak256Hash {}; 

    // 1. SWIFFT (Lattice)
    group.bench_function("SWIFFT (Lattice)", |b| {
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

    // 2. Keccak-256
    group.bench_function("Keccak-256", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            let result = keccak_hasher.hash_iter(bytes.iter().cloned());
            black_box(result)
        })
    });

    // 3. SHA-256 (Native)
    group.bench_function("SHA-256 (Native)", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let result = hasher.finalize();
            black_box(result)
        })
    });
    // 4. ✨ Poseidon2 (Algebraic Hash) ✨
    // 4. ✨ Poseidon2 (Algebraic Permutation) ✨
    group.bench_function("Poseidon2 (Permutation, BabyBear)", |b| {
        
        // 1. Plonky3 공식 BabyBear 전용 Poseidon2 초기화
        // (제네릭 에러를 피하기 위해 라이브러리에 내장된 기본 팩토리 함수를 사용합니다)
        // 🚨 만약 이 함수 이름에서 에러가 난다면, p3_baby_bear::Poseidon2BabyBear::new() 로 수정해 보세요!
        let mut poseidon2 = p3_baby_bear::default_babybear_poseidon2_16();

        b.iter_batched(
            || {
                // 2. BabyBear::zero() 대신 BabyBear::new(0) 사용
                let mut state = [BabyBear::new(0); 16];
                for i in 0..16 {
                    // 3. from_canonical_u32 대신 BabyBear::new() 사용
                    state[i] = BabyBear::new((i as u32) % 257);
                }
                state
            },
            |mut state| {
                // 코어 엔진(Permutation) 실행 시간 측정
                poseidon2.permute_mut(&mut state);
                black_box(state)
            },
            BatchSize::SmallInput,
        )
    });
    // 모든 벤치마크를 추가한 뒤 마지막에 딱 한 번만 호출합니다.
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = hash_comparison_bench
);
criterion_main!(benches);