//src/bin/trace_sha256.rs

use p3_baby_bear::BabyBear;
use p3_matrix::Matrix;
use lattice_bench::sha256::generate_sha256_trace;

fn measure(num_rows: usize) -> (usize, usize, usize) {
    let trace = generate_sha256_trace::<BabyBear>(num_rows);
    let w = trace.width();
    let h = trace.height();
    (w, h, w * h)
}

fn main() {
    println!("=== SHA-256 (bitwise) Trace Size Scaling ===\n");
    println!("{:>10} | {:>8} | {:>10} | {:>14}", "num_rows", "width", "height", "total_cells");
    println!("{}", "-".repeat(52));

    // generate_sha256_trace 는 num_rows 가 2의 거듭제곱이어야 함(내부 assert).
    // Keccak workload(1,10,100,1000 hashes)와 비슷한 규모 구간으로 2의 거듭제곱 선택.
    let workloads = [1usize << 8, 1 << 10, 1 << 12, 1 << 14]; // 256, 1024, 4096, 16384
    let mut last_total = 0;

    for &n in &workloads {
        let (w, h, total) = measure(n);
        println!(
            "{:>10} | {:>8} | {:>10} | {:>14}  [2^{}]",
            n, w, h, total, h.trailing_zeros()
        );
        last_total = total;
    }

    println!("\nTrace Size: {}", last_total);
}