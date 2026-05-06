import streamlit as st
import subprocess
import json
import os
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="ZKP Hash Benchmark", layout="wide")
st.title("⚡ ZKP 친화적 해시 vs 표준 암호 성능 벤치마크")
st.markdown("영지식 증명(STARK) 환경에서의 해시 함수 성능을 4가지 핵심 지표로 분석합니다.")

# --- 경로 설정 ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
CRITERION_DIR = os.path.join(PROJECT_ROOT, "target", "criterion", "Hash Comparison (Raw Bytes)")
# 추후 Rust 코드에서 아래 파일명으로 결과를 출력하도록 맞춰야 합니다.
MEMORY_JSON_PATH = os.path.join(PROJECT_ROOT, "dhat-heap.json") 
TRACE_JSON_PATH = os.path.join(PROJECT_ROOT, "trace_results.json")

# 분석 대상 해시 알고리즘 목록
ALGORITHMS = ["SWIFFT", "Keccak", "Poseidon", "SHA-256"]
INPUT_SIZE_BYTES = 1024  # 1KB 기준

def run_benchmark():
    with st.spinner("Rust 코어 엔진에서 전체 벤치마크를 수행 중입니다... (Criterion, Dhat, Trace)"):
        # Criterion 벤치마크 실행
        bench_res = subprocess.run("cargo bench", shell=True, capture_output=True, text=True)
        # Memory & Trace 벤치마크 실행 (바이너리가 생성되었다고 가정)
        # subprocess.run("cargo run --release --bin memory_bench", shell=True)
        # subprocess.run("cargo run --release --bin trace_bench", shell=True)
        
        if bench_res.returncode == 0:
            st.success("벤치마크 분석 완료!")
            st.rerun()
        else:
            st.error("벤치마크 실행 실패")
            st.code(bench_res.stderr)

def get_latency(keyword):
    """Criterion에서 실행 시간(Latency) 로드 (단위: µs)"""
    if not os.path.exists(CRITERION_DIR):
        return None
    folders = [f for f in os.listdir(CRITERION_DIR) if os.path.isdir(os.path.join(CRITERION_DIR, f))]
    target_folder = next((f for f in folders if keyword.lower() in f.lower()), None)
    
    if target_folder:
        json_path = os.path.join(CRITERION_DIR, target_folder, "new", "estimates.json")
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
                return data['mean']['point_estimate'] / 1000.0
    return None

def get_memory_usage(keyword):
    """Dhat JSON에서 메모리 피크 로드 (단위: KB) - 현재는 더미 데이터"""
    # 실제 dhat-heap.json 파싱 로직은 구조에 따라 달라지므로, 
    # 여기서는 추후 연동을 위한 자리 표시자(Placeholder)로 구성합니다.
    dummy_data = {"SWIFFT": 15.2, "Keccak": 2.1, "Poseidon": 4.5, "SHA-256": 1.8}
    return dummy_data.get(keyword, None)

def get_trace_size(keyword):
    """Trace 분석 결과에서 셀(Cell) 개수 로드 - 현재는 더미 데이터"""
    dummy_data = {"SWIFFT": 65536, "Keccak": 131072, "Poseidon": 8192, "SHA-256": 262144}
    return dummy_data.get(keyword, None)

# 상단 버튼
if st.button("🚀 전체 시스템 벤치마크 실행"):
    run_benchmark()

st.divider()

# --- 데이터 수집 ---
results = []
for algo in ALGORITHMS:
    latency = get_latency(algo)
    throughput = (INPUT_SIZE_BYTES / (latency * 1e-6)) / (1024 * 1024) if latency else None # MB/s
    memory = get_memory_usage(algo)
    trace = get_trace_size(algo)
    
    # 데이터가 존재하는 알고리즘만 추가
    if latency is not None:
        results.append({
            "Algorithm": algo,
            "Latency (µs)": latency,
            "Throughput (MB/s)": throughput,
            "Memory (KB)": memory,
            "Trace Size (Cells)": trace
        })

df = pd.DataFrame(results)

# --- 화면 렌더링 ---
if not df.empty:
    # 4개의 탭으로 지표 분리
    tab1, tab2, tab3, tab4 = st.tabs([
        "⏱️ 실행 시간 (Latency)", 
        "🚀 처리량 (Throughput)", 
        "💾 메모리 사용량 (Heap Peak)", 
        "🧩 ZK 트레이스 크기 (Rows x Cols)"
    ])
    
    with tab1:
        st.subheader("1개의 해시 생성에 걸리는 순수 시간 (낮을수록 좋음)")
        fig1 = px.bar(df, x="Algorithm", y="Latency (µs)", color="Algorithm", text_auto='.2f')
        st.plotly_chart(fig1, use_container_width=True)

    with tab2:
        st.subheader("초당 처리 가능한 데이터량 (높을수록 좋음)")
        # 속도가 느린 ZK 해시와 일반 해시 간의 격차가 크므로 로그 스케일 적용 고려 가능
        fig2 = px.bar(df, x="Algorithm", y="Throughput (MB/s)", color="Algorithm", text_auto='.2f')
        st.plotly_chart(fig2, use_container_width=True)

    with tab3:
        st.subheader("연산 중 할당되는 최대 힙 메모리 (낮을수록 좋음)")
        st.info("💡 추후 `dhat` 프로파일러가 생성한 실제 데이터가 연동됩니다.")
        fig3 = px.bar(df, x="Algorithm", y="Memory (KB)", color="Algorithm", text_auto='.2f')
        st.plotly_chart(fig3, use_container_width=True)

    with tab4:
        st.subheader("STARK 증명 행렬의 총 셀(Cell) 개수 (낮을수록 증명 시간이 짧음)")
        st.info("💡 영지식 증명 성능의 핵심입니다. 추후 Plonky3 AIR 제약 조건 결과가 연동됩니다.")
        fig4 = px.bar(df, x="Algorithm", y="Trace Size (Cells)", color="Algorithm", text_auto='.0f')
        st.plotly_chart(fig4, use_container_width=True)

    # 전체 데이터 표 요약
    st.divider()
    st.markdown("### 📋 종합 성능 요약표")
    st.dataframe(df.style.highlight_min(subset=['Latency (µs)', 'Memory (KB)', 'Trace Size (Cells)'], color='lightgreen')
                         .highlight_max(subset=['Throughput (MB/s)'], color='lightgreen'), 
                 use_container_width=True)

else:
    st.warning("벤치마크 데이터를 찾을 수 없습니다. 상단의 실행 버튼을 누르거나 `cargo bench`를 실행해 주세요.")
    if os.path.exists(CRITERION_DIR):
        with st.expander("🔎 실제 생성된 폴더 목록 확인 (디버깅용)"):
            st.write(os.listdir(CRITERION_DIR))