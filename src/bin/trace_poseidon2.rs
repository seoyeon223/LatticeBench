// src/bin/trace_poseidon2.rs
//
// 워크로드 단위를 다른 trace_* 바이너리와 통일했다.
// 통일 기준: "1024바이트 입력 1회 해싱"
//   - Poseidon2 는 본래 바이트가 아닌 BabyBear 필드 원소를 처리한다.
//   - BabyBear 원소 = 약 4바이트(31bit). 1024 바이트 ≈ 256 원소.
//   - PaddingFreeSponge(rate=8) 가정 시 256 / 8 = 32 permutation.
//     (hash_bench.rs 의 PaddingFreeSponge<_, 16, 8, 4> 와 일치)
//   - 따라서 num_perm = 32 가 "1024바이트 1회 해싱"에 대응.
//
// 주의:
//   1. 바이트 환산 자체가 부정확하다 (4바이트 → 31bit 모듈로 편향).
//      Poseidon2 비교는 본질적으로 근사이며, 본 정규화는 그중에서도
//      가장 자연스러운 환산일 뿐이다.
//   2. generate_trace_rows 는 num_hashes 가 2의 거듭제곱 일 것을 요구.
//      32 = 2^5 이므로 OK.
//   3. 워크로드가 작아 next_power_of_two padding 비율이 클 수 있다.
//      이는 "같은 1024B 처리"의 정직성을 위해 감수한다.
//
// const 파라미터는 Plonky3 공식 예제
//   poseidon2-air/examples/prove_poseidon2_baby_bear_keccak_zk.rs
// 와 동일 (추측값 아님).

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_matrix::Matrix;
use rand::SeedableRng;
use rand::rngs::SmallRng;

const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 1;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

type LL = GenericPoseidon2LinearLayersBabyBear;
type MyAir = Poseidon2Air<
    BabyBear,
    LL,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

// 1024 바이트 1회 해싱에 필요한 permutation 수 (PaddingFreeSponge rate=8 가정).
// 1024B / 4B per BabyBear = 256 elements; 256 / 8 (rate) = 32 permutations.
const PERMS_PER_1KB: usize = 32;
const NORMALIZED_INPUT_BYTES: usize = 1024;

fn main() {
    println!("=== Plonky3 Poseidon2 (BabyBear w16) Trace Size ===");
    println!(
        "workload unit: \"{} bytes input, 1 hash call\" \u{2248} {} permutations (rate=8 BabyBear elems, 4B/elem)",
        NORMALIZED_INPUT_BYTES, PERMS_PER_1KB
    );
    println!("note: byte\u{2192}field conversion is approximate (see file header)\n");

    let mut rng = SmallRng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let air: MyAir = Poseidon2Air::new(constants);

    // 스케일링 관찰용 (참고)
    println!("--- Scaling reference (not the primary metric) ---");
    println!("{:>10} | {:>8} | {:>10} | {:>14}", "num_perm", "width", "height", "total_cells");
    println!("{}", "-".repeat(52));
    let scaling = [32usize, 256, 2048, 16384];
    for &n in &scaling {
        let trace = air.generate_trace_rows(n, 0);
        let w = trace.width();
        let h = trace.height();
        let total = w * h;
        println!(
            "{:>10} | {:>8} | {:>10} | {:>14}  [2^{}]",
            n, w, h, total, h.trailing_zeros()
        );
    }

    // 통일 워크로드 = 1024B ≈ 32 perm
    println!("\n--- Normalized workload (1024B ≈ {} permutations) ---", PERMS_PER_1KB);
    let trace = air.generate_trace_rows(PERMS_PER_1KB, 0);
    let w = trace.width();
    let h = trace.height();
    let total = w * h;
    println!("width={} height={} cells={}", w, h, total);
    println!("Input bytes: {} (approx, via 4B/elem conversion)", NORMALIZED_INPUT_BYTES);
    println!("Cells per byte: {:.2}", total as f64 / NORMALIZED_INPUT_BYTES as f64);

    // 대시보드 정규식 호환: 마지막 줄에 통일 워크로드 기준 셀 수.
    println!("\nTrace Size: {}", total);
}