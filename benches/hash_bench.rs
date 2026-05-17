use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rand::Rng;
use rand::RngExt;
// 새로 바뀐 SWIFFT 구조체들 가져오기
use lattice_bench::{
    SwifftHasherNaive, SwifftPolyNaive, 
    SwifftHasherNTT, SwifftHasherSimd, 
    SwifftPoly
};

// 다른 해시 알고리즘들 가져오기
use p3_keccak::Keccak256Hash;
use p3_sha256::Sha256;
use p3_symmetric::CryptographicHasher;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_symmetric::PaddingFreeSponge;
use pprof::criterion::PProfProfiler;
use pprof::criterion::Output;

/// 256바이트 청크를 Naive 버전의 입력인 [SwifftPolyNaive; 16]으로 변환하는 헬퍼 함수
fn bytes_to_naive_polys(chunk: &[u8]) -> [SwifftPolyNaive; 16] {
    let mut polys = [SwifftPolyNaive::new(); 16];
    for i in 0..16 {
        let poly_chunk = &chunk[i * 16..(i + 1) * 16];
        for j in 0..16 {
            let byte = poly_chunk[j];
            for b in 0..4 {
                // 1바이트에서 2비트씩 추출하여 계수로 매핑
                polys[i].coeffs[j * 4 + b] = ((byte >> (b * 2)) & 0x03) as u16;
            }
        }
    }
    polys
}

// 🟢 모든 벤치마크를 하나로 통합한 메인 함수
fn hash_comparison_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ZKP_Hashes_1KB");
    
    // 처리량(Throughput) 측정 설정: 1024 바이트 기준
    group.throughput(Throughput::Bytes(1024));

    // ==========================================
    // [초기화 1] 공통 더미 데이터 생성 (진짜 난수 1024 바이트)
    // ==========================================
    let mut rng = rand::rng();
    let mut raw_data = vec![0u8; 1024];
    rng.fill(&mut raw_data[..]);

    // ==========================================
    // [초기화 2] 공통 키 생성 및 해시 인스턴스 준비
    // ==========================================
    let mut dummy_keys_i32 = [[0i32; 64]; 16];
    for i in 0..16 {
        for j in 0..64 {
            dummy_keys_i32[i][j] = ((i + j) % 257) as i32;
        }
    }

    let swifft_naive = SwifftHasherNaive::new();
    let swifft_scalar = SwifftHasherNTT::new(&dummy_keys_i32);
    let swifft_simd = SwifftHasherSimd::new(&dummy_keys_i32);
    let keccak_hasher = Keccak256Hash {};
    let sha256_hasher = Sha256 {};

    // Poseidon용 데이터 세팅 (u32 난수 -> BabyBear 변환)
    let poseidon2_perm = p3_baby_bear::default_babybear_poseidon2_16();
    let poseidon_hasher = PaddingFreeSponge::<_, 16, 8, 4>::new(poseidon2_perm);
    let poseidon_data: Vec<BabyBear> = (0..256)
        .map(|_| BabyBear::new(rng.random::<u32>() % 2013265921))
        .collect();

    // ==========================================
    // 🐢 1. SWIFFT (Naive / O(N^2) 곱셈) 측정
    // ==========================================
    group.bench_function("SWIFFT-Naive", |b| {
        b.iter(|| {
            for chunk in raw_data.chunks_exact(256) {
                let polys_naive = bytes_to_naive_polys(chunk);
                black_box(swifft_naive.compress(&polys_naive));
            }
        });
    });

    // ==========================================
    // 🟢 2. SWIFFT (Scalar / NTT 기반 O(N log N)) 측정
    // ==========================================
    group.bench_function("SWIFFT-Scalar", |b| {
        b.iter(|| {
            for chunk in raw_data.chunks_exact(256) {
                black_box(swifft_scalar.hash(chunk));
            }
        });
    });

    // ==========================================
    // 🚀 3. SWIFFT (AVX2 / SIMD 고속화) 측정
    // ==========================================
    group.bench_function("SWIFFT-AVX2", |b| {
        b.iter(|| {
            for chunk in raw_data.chunks_exact(256) {
                black_box(swifft_simd.hash(chunk));
            }
        });
    });

    // ==========================================
    // 🦇 4. Keccak-256 측정
    // ==========================================
    group.bench_function("Keccak-256", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            black_box(keccak_hasher.hash_iter(bytes.iter().cloned()));
        })
    });

    // ==========================================
    // 🔒 5. SHA-256 측정
    // ==========================================
    group.bench_function("SHA-256", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            black_box(sha256_hasher.hash_iter(bytes.iter().cloned()));
        })
    });

    // ==========================================
    // 🔱 6. Poseidon2 측정
    // ==========================================
    group.bench_function("Poseidon2", |b| {
        b.iter(|| {
            let data = black_box(&poseidon_data);
            black_box(poseidon_hasher.hash_iter(data.iter().cloned()));
        })
    });

    // 🛑 그룹 측정 종료 (반드시 함수 맨 끝에 한 번만!)
    group.finish();
}

// 🟢 매크로는 반드시 파일 맨 밑에 한 번씩만 존재해야 합니다.
criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = hash_comparison_bench
);
criterion_main!(benches);