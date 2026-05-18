//src/bin/trace_keccak.rs
use p3_baby_bear::BabyBear;
use p3_keccak_air::generate_trace_rows;
use p3_matrix::Matrix;

fn measure(num_hashes: usize) -> (usize, usize, usize) {
    let inputs = vec![[0u64; 25]; num_hashes];
    // 두 번째 인자 = extra_capacity_bits. 크기 측정에는 0.
    let trace = generate_trace_rows::<BabyBear>(inputs, 0);
    let w = trace.width();
    let h = trace.height();
    (w, h, w * h)
}

fn main() {
    println!("=== Plonky3 Keccak-256 Trace Size Scaling ===\n");
    println!("{:>10} | {:>8} | {:>10} | {:>14}", "num_hash", "width", "height", "total_cells");
    println!("{}", "-".repeat(52));

    let workloads = [1usize, 10, 100, 1000];
    let mut last_total = 0;

    for &n in &workloads {
        let (w, h, total) = measure(n);
        let pow = if h.is_power_of_two() {
            format!("2^{}", h.trailing_zeros())
        } else {
            "(non-pow2)".to_string()
        };
        println!("{:>10} | {:>8} | {:>10} | {:>14}  [{}]", n, w, h, total, pow);
        last_total = total;
    }

    // 대시보드 정규식 호환: 마지막(최대 workload) 기준 한 줄
    println!("\nTrace Size: {}", last_total);
}