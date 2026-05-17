use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_baby_bear::BabyBear;

const M: usize = 16; 
const N: usize = 64; 

// 🟢 <F: Field> 제네릭을 없애고, BabyBear 타입을 직접 명시하여 컴파일러의 혼란을 막습니다!
fn generate_swifft_trace(data: &[u8]) -> RowMajorMatrix<BabyBear> {
    let mut values = Vec::new();
    let num_blocks = data.len() / 256; 

    let width = N;

    for _block in 0..num_blocks {
        let mut rows_in_block = 0;

        for _poly in 0..M {
            // (a) F::zero() 대신 BabyBear::new(0) 사용
            values.extend(vec![BabyBear::new(0); width]);
            rows_in_block += 1;

            // (b) F::one() 대신 BabyBear::new(1) 사용
            for _layer in 0..6 {
                values.extend(vec![BabyBear::new(1); width]); 
                rows_in_block += 1;
            }

            // (c) F::from_canonical_u32(2) 대신 BabyBear::new(2) 사용
            values.extend(vec![BabyBear::new(2); width]);
            rows_in_block += 1;
        }

        // 2. INTT
        for _layer in 0..6 {
            values.extend(vec![BabyBear::new(1); width]);
            rows_in_block += 1;
        }

        // 3. Padding to nearest power of 2
        let padded_rows = 256; 
        for _ in rows_in_block..padded_rows {
            values.extend(vec![BabyBear::new(0); width]);
        }
    }

    RowMajorMatrix::new(values, width)
}

fn main() {
    println!("⚙️ Setting up SWIFFT STARK Trace Generator...\n");

    let data = vec![0u8; 1024];

    println!("Generating SWIFFT Trace for 1KB data...");
    
    // 🟢 제네릭 타입 파라미터(::<BabyBear>) 제거됨
    let trace = generate_swifft_trace(&data);

    let width = trace.width();
    let height = trace.height();
    let total_cells = width * height;

    println!("✅ Trace successfully generated!");
    println!("📊 Dimensions: {} rows × {} columns", height, width);
    
    println!("Trace Size: {}", total_cells);
}