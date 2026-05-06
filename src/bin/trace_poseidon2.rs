fn main() {
    println!("=== Plonky3 Poseidon2 Trace Size Measurement (Native Field Estimator) ===");

    // 타입 추론의 모호함을 없애기 위해 usize 타입을 명시적으로 선언합니다.
    let num_hashes: usize = 10;
    
    let width: usize = 16; 
    let rows_per_hash: usize = 30;
    
    let required_rows = num_hashes * rows_per_hash;
    // 이제 컴파일러가 required_rows가 usize임을 알기 때문에 메서드를 호출할 수 있습니다.
    let height = required_rows.next_power_of_two();
    let total_cells = width * height;

    println!("\n[ 측정 결과 ]");
    println!(" - 연산 횟수: {} 번", num_hashes);
    println!(" - Columns (Width): {}", width); 
    println!(" - Rows (Height): {} (2^{})", height, height.ilog2());
    println!(" - Total Trace Cells: {} cells", total_cells);

    // Padding 확인
    let num_hashes_large: usize = 1000;
    let required_rows_large = num_hashes_large * rows_per_hash;
    let height_large = required_rows_large.next_power_of_two();
    
    println!("\n[ Padding(2^k) 확인용 실험 ]");
    println!(" - {} 번 연산 시 Rows: {} (2^{})", 
        num_hashes_large, 
        height_large, 
        height_large.ilog2()
    );
}