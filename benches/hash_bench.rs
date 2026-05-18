use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rand::Rng;
use rand::RngExt;
// SWIFFT 구조체들
use lattice_bench::{
    SwifftHasherNaive, SwifftPolyNaive,
    SwifftHasherNTT, SwifftHasherSimd,
    SwifftPoly,
};

// 다른 해시 알고리즘들
use p3_keccak::Keccak256Hash;
use p3_sha256::Sha256;
use p3_symmetric::CryptographicHasher;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_symmetric::PaddingFreeSponge;
use pprof::criterion::PProfProfiler;
use pprof::criterion::Output;

/// 256바이트 청크를 Naive 입력 [SwifftPolyNaive; 16]으로 변환
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

// BabyBear 소수 p = 2^31 - 2^27 + 1
const BABYBEAR_P: u32 = 2013265921;

/// 공통 raw_data 에서 결정론적으로 BabyBear 필드 원소 256개 생성.
/// 4바이트(little-endian u32) -> BabyBear::new(u32 % p).
///
/// 주의: % p 로 인한 모듈로 편향이 존재하나, Poseidon2 순열은 입력값과
/// 무관한 고정시간 연산이므로 처리 시간 측정에는 영향이 없다.
/// (리포트 한계 절에 명시)
fn raw_data_to_babybear(raw: &[u8], count: usize) -> Vec<BabyBear> {
    (0..count)
        .map(|i| {
            let off = (i * 4) % raw.len();
            // raw 가 1024바이트이므로 4*256 = 1024 로 정확히 소비됨
            let b = [
                raw[off],
                raw[(off + 1) % raw.len()],
                raw[(off + 2) % raw.len()],
                raw[(off + 3) % raw.len()],
            ];
            let v = u32::from_le_bytes(b);
            BabyBear::new(v % BABYBEAR_P)
        })
        .collect()
}

fn hash_comparison_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ZKP_Hashes_1KB");

    // 모든 함수: 동일한 1024바이트 raw_data 기준 처리량
    group.throughput(Throughput::Bytes(1024));

    // ── [초기화 1] 공통 입력: 진짜 난수 1024바이트 ──────────────
    let mut rng = rand::rng();
    let mut raw_data = vec![0u8; 1024];
    rng.fill(&mut raw_data[..]);

    // ── [초기화 2] 키 및 해시 인스턴스 ─────────────────────────
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

    // Poseidon2: 입력을 공통 raw_data 에서 결정론적으로 파생.
    // 변환은 측정 구간(iter) 밖에서 1회만 수행.
    let poseidon2_perm = p3_baby_bear::default_babybear_poseidon2_16();
    let poseidon_hasher = PaddingFreeSponge::<_, 16, 8, 4>::new(poseidon2_perm);
    let poseidon_data: Vec<BabyBear> = raw_data_to_babybear(&raw_data, 256);

    // ── 1. SWIFFT Naive (O(N^2)) ──────────────────────────────
    // 세 SWIFFT 변종 모두 "256바이트 -> 해시" 전체 파이프라인을 측정.
    // NTT/SIMD 의 hash() 가 바이트 언패킹을 내부에 포함하므로,
    // Naive 도 bytes_to_naive_polys 를 iter 안에 두어 경계를 일치시킴.
    group.bench_function("SWIFFT-Naive", |b| {
        b.iter(|| {
            for chunk in raw_data.chunks_exact(256) {
                let polys_naive = bytes_to_naive_polys(chunk);
                black_box(swifft_naive.compress(black_box(&polys_naive)));
            }
        });
    });

    // ── 2. SWIFFT Scalar (NTT, O(N log N)) ────────────────────
    group.bench_function("SWIFFT-Scalar", |b| {
        b.iter(|| {
            for chunk in raw_data.chunks_exact(256) {
                black_box(swifft_scalar.hash(black_box(chunk)));
            }
        });
    });

    // ── 3. SWIFFT AVX2 (SIMD) ─────────────────────────────────
    group.bench_function("SWIFFT-AVX2", |b| {
        b.iter(|| {
            for chunk in raw_data.chunks_exact(256) {
                black_box(swifft_simd.hash(black_box(chunk)));
            }
        });
    });

    // ── 4. Keccak-256 ─────────────────────────────────────────
    group.bench_function("Keccak-256", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            black_box(keccak_hasher.hash_iter(bytes.iter().cloned()));
        })
    });

    // ── 5. SHA-256 ────────────────────────────────────────────
    group.bench_function("SHA-256-style bitwise circuit", |b| {
        b.iter(|| {
            let bytes = black_box(&raw_data);
            black_box(sha256_hasher.hash_iter(bytes.iter().cloned()));
        })
    });

    // ── 6. Poseidon2 ──────────────────────────────────────────
    // 입력은 raw_data 에서 파생된 poseidon_data (변환은 측정 밖).
    group.bench_function("Poseidon2", |b| {
        b.iter(|| {
            let data = black_box(&poseidon_data);
            black_box(poseidon_hasher.hash_iter(data.iter().cloned()));
        })
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = hash_comparison_bench
);
criterion_main!(benches);