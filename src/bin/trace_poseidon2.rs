//src/bin/trace_poseidon2.rs
//
// Poseidon2 (BabyBear, width-16) trace 크기 측정.
// const 파라미터는 Plonky3 공식 예제
//   poseidon2-air/examples/prove_poseidon2_baby_bear_keccak_zk.rs
// 와 동일하게 맞췄다 (추측값 아님, 소스 확정).

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_matrix::Matrix; // .width() / .height()
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

fn main() {
    println!("=== Plonky3 Poseidon2 (BabyBear w16) Trace Size Scaling ===\n");

    // 공식 예제와 동일한 RNG/상수 생성 방식
    let mut rng = SmallRng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let air: MyAir = Poseidon2Air::new(constants);

    println!(
        "{:>10} | {:>8} | {:>10} | {:>14}",
        "num_perm", "width", "height", "total_cells"
    );
    println!("{}", "-".repeat(52));

    // num_hashes 는 내부 generate_trace_rows 의 assert(is_power_of_two) 때문에
    // 반드시 2의 거듭제곱. Keccak/SHA-256 벤치와 같은 height 구간 사용.
    let workloads = [256usize, 1024, 4096, 16384];
    let mut last_total = 0;

    for &n in &workloads {
        // Poseidon2Air::generate_trace_rows(num_hashes, extra_capacity_bits)
        // - 내부에서 SmallRng 로 입력 자동 생성
        // - extra_capacity_bits = 0 (크기 측정용)
        let trace = air.generate_trace_rows(n, 0);
        let w = trace.width();
        let h = trace.height();
        let total = w * h;
        println!(
            "{:>10} | {:>8} | {:>10} | {:>14}  [2^{}]",
            n,
            w,
            h,
            total,
            h.trailing_zeros()
        );
        last_total = total;
    }

    // 대시보드 정규식 호환 (Keccak/SHA-256 벤치와 동일 포맷)
    println!("\nTrace Size: {}", last_total);
}