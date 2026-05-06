use p3_baby_bear::BabyBear;
use p3_keccak_air::generate_trace_rows; // KeccakAir 제거 (경고 해결)
use p3_matrix::Matrix;

fn main() {
    println!("=== Plonky3 Keccak-256 Trace Size Measurement ===");

    // 1. 측정할 해시 연산의 횟수
    let num_hashes = 10;
    
    // Keccak 연산을 위한 더미 입력값 생성 (25개 u64 배열)
    let inputs = vec![[0u64; 25]; num_hashes];

    // 2. 두 번째 인자(min_rows)로 0을 전달합니다.
    let trace_matrix = generate_trace_rows::<BabyBear>(inputs, 0);

    // 3. 메모리에 생성된 행렬(Matrix)의 크기 측정
    let width = trace_matrix.width();
    let height = trace_matrix.height();
    let total_cells = width * height;

    println!("\n[ 측정 결과 ]");
    println!(" - 연산 횟수: {} 번", num_hashes);
    println!(" - Columns (Width): {}", width);
    println!(" - Rows (Height): {} (2^{})", height, height.ilog2());
    println!(" - Total Trace Cells: {} cells", total_cells);

    // 4. 연산 횟수를 늘렸을 때의 변화 확인
    println!("\n[ Padding(2^k) 확인용 실험 ]");
    let num_hashes_large = 1000;
    let inputs_large = vec![[0u64; 25]; num_hashes_large];
    
    // 여기도 두 번째 인자로 0을 전달합니다.
    let trace_matrix_large = generate_trace_rows::<BabyBear>(inputs_large, 0);
    
    println!(" - {} 번 연산 시 Rows: {} (2^{})", 
        num_hashes_large, 
        trace_matrix_large.height(), 
        trace_matrix_large.height().ilog2()
    );
}