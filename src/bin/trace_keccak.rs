// src/bin/trace_keccak.rs
//
// 워크로드 단위를 다른 trace_* 바이너리와 통일했다.
// 통일 기준: "1024바이트 입력 1회 해싱"
//   - Keccak-256 의 sponge rate 는 136 바이트.
//   - 1024 바이트를 흡수하려면 ceil(1024 / 136) = 8 permutation 필요
//     (정확히는 7.53 + 패딩 → 8).
//   - 따라서 num_hashes = 8 이 "1024바이트 1회 해싱"에 대응한다.
//
// 다른 워크로드(스케일링 관찰용)는 보조로 함께 출력한다.
// 대시보드는 마지막 줄 "Trace Size: N" 만 정규식으로 읽으므로,
// 마지막에 통일 워크로드(8 perm = 1024B) 의 셀 수를 출력한다.

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

// 1024 바이트 1회 해싱에 필요한 Keccak permutation 수.
// rate=136 → ceil(1024/136) = 8 (패딩 포함).
const PERMS_PER_1KB: usize = 8;
const NORMALIZED_INPUT_BYTES: usize = 1024;

fn main() {
    println!("=== Plonky3 Keccak-256 Trace Size ===");
    println!(
        "workload unit: \"{} bytes input, 1 hash call\" = {} permutations (rate=136B)\n",
        NORMALIZED_INPUT_BYTES, PERMS_PER_1KB
    );

    // 스케일링 관찰용 (참고)
    println!("--- Scaling reference (not the primary metric) ---");
    println!("{:>10} | {:>8} | {:>10} | {:>14}", "num_perm", "width", "height", "total_cells");
    println!("{}", "-".repeat(52));
    let scaling = [1usize, 8, 64, 512];
    for &n in &scaling {
        let (w, h, total) = measure(n);
        let pow = if h.is_power_of_two() {
            format!("2^{}", h.trailing_zeros())
        } else {
            "(non-pow2)".to_string()
        };
        println!("{:>10} | {:>8} | {:>10} | {:>14}  [{}]", n, w, h, total, pow);
    }

    // 통일 워크로드 = 1024B = 8 perm
    println!("\n--- Normalized workload (1024B = {} permutations) ---", PERMS_PER_1KB);
    let (w, h, total) = measure(PERMS_PER_1KB);
    println!("width={} height={} cells={}", w, h, total);
    println!("Input bytes: {}", NORMALIZED_INPUT_BYTES);
    println!("Cells per byte: {:.2}", total as f64 / NORMALIZED_INPUT_BYTES as f64);

    // 대시보드 정규식 호환: 마지막 줄에 통일 워크로드 기준 셀 수.
    println!("\nTrace Size: {}", total);
}