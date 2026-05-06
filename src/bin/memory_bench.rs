use dhat::{Alloc, Profiler};
use p3_keccak::Keccak256Hash;
use p3_sha256::Sha256;
use p3_symmetric::CryptographicHasher;

// 🟢 [수정 핵심] p3_baby_bear에서 BabyBear용으로 최적화된 Poseidon2 앨리어스를 가져옵니다.
use p3_baby_bear::{BabyBear, Poseidon2BabyBear}; 
use p3_symmetric::{PaddingFreeSponge};
use lattice_bench::{SwifftHasher, SwifftPoly};

// 글로벌 할당자 등록
#[global_allocator]
static ALLOC: Alloc = Alloc;

fn main() {
    // 힙 프로파일링 시작
    let _profiler = Profiler::new_heap();

    println!("Starting Memory Benchmark for Hash Algorithms...\n");

    // ----------------------------------------------------
    // 1. Keccak-256 측정 (바이트 단위)
    // ----------------------------------------------------
    {
        let keccak = Keccak256Hash {};
        let data = vec![0u8; 1024]; 
        let _hash = keccak.hash_iter(data.iter().cloned());
    }

    // ----------------------------------------------------
    // 2. SHA-256 측정 (바이트 단위)
    // ----------------------------------------------------
    {
        let sha256 = Sha256 {}; 
        let data = vec![0u8; 1024]; 
        let _hash = sha256.hash_iter(data.iter().cloned());
    }

    // ----------------------------------------------------
    // 3. Poseidon2 측정 (유한체 Field 단위)
    // ----------------------------------------------------
    {
        // 🟢 [핵심 수정] rand 0.10 버전에 맞추어 rng() 함수 사용
        let mut rng = rand::rng(); 
        
        // Plonky3의 Poseidon2BabyBear는 내부적으로 최신 Rng 트레이트를 요구하므로
        // 위에서 생성한 rng와 타입이 완벽하게 호환됩니다.
        let poseidon_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);
        
        // 스펀지 구조(Sponge Construction) 래퍼 적용
        let hasher = PaddingFreeSponge::<_, 16, 8, 4>::new(poseidon_perm);
        
        // 메모리 할당: BabyBear::default()를 통해 값 0으로 초기화
        let data = vec![BabyBear::default(); 256]; 
        
        // 해시 반복 수행
        let _hash = hasher.hash_iter(data.iter().cloned());
    }

    // ----------------------------------------------------
    // 4. SWIFFT 측정 (격자 다항식 단위)
    // ----------------------------------------------------
    {
        let swifft = SwifftHasher::new();
        let inputs = [SwifftPoly::new(); 16];
        let _res = swifft.compress(&inputs);
    }

    println!("Benchmark finished. Check 'dhat-heap.json' in your root directory.");
}