import streamlit as st
import subprocess
import json
import os
import re
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="ZKP Hash Benchmark", layout="wide")
st.title("⚡ ZKP 친화적 해시 vs 표준 암호 성능 벤치마크")
st.markdown("영지식 증명(STARK) 환경에서의 해시 함수 성능을 4가지 핵심 지표로 분석합니다.")

# --- 경로 설정 ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
CRITERION_DIR = os.path.join(PROJECT_ROOT, "target", "criterion")

# Rust에서 측정 후 결과를 저장할 JSON 파일 경로
MEMORY_JSON_PATH = os.path.join(PROJECT_ROOT, "memory_results.json") 
TRACE_JSON_PATH = os.path.join(PROJECT_ROOT, "trace_results.json")

# 분석 대상 해시 알고리즘 목록
ALGORITHMS = ["SWIFFT", "Keccak", "Poseidon", "SHA-256"]
INPUT_SIZE_BYTES = 1024  # 1KB 기준

def run_benchmark():
    with st.spinner("Rust 코어 엔진에서 전체 벤치마크를 수행 중입니다... (1~2분 정도 소요될 수 있습니다)"):
        # 1. Criterion 실행 (시간/처리량)
        bench_res = subprocess.run("cargo bench", shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT)
        
        # 2. Memory 벤치마크 실행 (memory_bench.rs가 memory_results.json을 생성한다고 가정)
        mem_res = subprocess.run("cargo run --release --bin memory_bench", shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT)
        
        # 3. Trace 벤치마크 실행 (각 알고리즘별 bin 파일을 실행하여 트레이스 크기를 JSON으로 병합)
        trace_data = {}
        binaries = {
            "SHA-256": "trace_sha256",
            "Keccak": "trace_keccak",
            "Poseidon": "trace_poseidon2",
            "SWIFFT": "trace_swifft" # SWIFFT 트레이스용 bin이 있다고 가정
        }
        
        for algo, bin_name in binaries.items():
            res = subprocess.run(f"cargo run --release --bin {bin_name}", shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT)
            # Rust stdout에서 'Trace Size: 65536' 같은 패턴을 정규식으로 추출
            match = re.search(r'Trace Size:\s*(\d+)', res.stdout, re.IGNORECASE)
            if match:
                trace_data[algo] = int(match.group(1))
        
        # 파싱한 Trace 데이터를 JSON으로 저장
        if trace_data:
            with open(TRACE_JSON_PATH, "w") as f:
                json.dump(trace_data, f)
        
        if bench_res.returncode == 0:
            st.success("벤치마크 분석 완료!")
            st.rerun()
        else:
            st.error("벤치마크 실행 실패 (자세한 에러는 터미널을 확인하세요)")
            with st.expander("에러 로그 보기"):
                st.code(bench_res.stderr)

def get_latency(keyword):
    """Criterion에서 실행 시간(Latency) 로드 (단위: µs)"""
    if not os.path.exists(CRITERION_DIR):
        return None
        
    # 'Hash Comparison (Raw Bytes)' 폴더 또는 유사한 벤치마크 그룹 폴더 탐색
    benchmark_groups = [f for f in os.listdir(CRITERION_DIR) if os.path.isdir(os.path.join(CRITERION_DIR, f)) and f != "report"]
    
    for group in benchmark_groups:
        group_path = os.path.join(CRITERION_DIR, group)
        folders = [f for f in os.listdir(group_path) if os.path.isdir(os.path.join(group_path, f))]
        
        # 폴더명(예: "sha-256", "poseidon2")이 keyword를 포함하는지 확인
        target_folder = next((f for f in folders if keyword.replace("-", "").lower() in f.replace("-", "").lower()), None)
        
        if target_folder:
            json_path = os.path.join(group_path, target_folder, "new", "estimates.json")
            if os.path.exists(json_path):
                with open(json_path, 'r') as f:
                    data = json.load(f)
                    return data['mean']['point_estimate'] / 1000.0 # ns -> µs 변환
    return None

def get_memory_usage(keyword):
    """Memory JSON에서 메모리 피크 로드 (단위: KB)"""
    if not os.path.exists(MEMORY_JSON_PATH):
        return None
    try:
        with open(MEMORY_JSON_PATH, 'r') as f:
            data = json.load(f)
            return data.get(keyword, None)
    except Exception:
        return None

def get_trace_size(keyword):
    """Trace JSON에서 셀(Cell) 개수 로드"""
    if not os.path.exists(TRACE_JSON_PATH):
        return None
    try:
        with open(TRACE_JSON_PATH, 'r') as f:
            data = json.load(f)
            return data.get(keyword, None)
    except Exception:
        return None

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
    
    # 하나라도 데이터가 측정되었다면 표에 추가
    if any(v is not None for v in [latency, memory, trace]):
        results.append({
            "Algorithm": algo,
            "Latency (µs)": latency if latency else 0,
            "Throughput (MB/s)": throughput if throughput else 0,
            "Memory (KB)": memory if memory else 0,
            "Trace Size (Cells)": trace if trace else 0
        })

df = pd.DataFrame(results)

# --- 화면 렌더링 ---
if not df.empty:
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
        fig2 = px.bar(df, x="Algorithm", y="Throughput (MB/s)", color="Algorithm", text_auto='.2f')
        st.plotly_chart(fig2, use_container_width=True)

    with tab3:
        st.subheader("연산 중 할당되는 최대 힙 메모리 (낮을수록 좋음)")
        fig3 = px.bar(df, x="Algorithm", y="Memory (KB)", color="Algorithm", text_auto='.2f')
        st.plotly_chart(fig3, use_container_width=True)

    with tab4:
        st.subheader("STARK 증명 행렬의 총 셀(Cell) 개수 (낮을수록 증명 시간이 짧음)")
        fig4 = px.bar(df, x="Algorithm", y="Trace Size (Cells)", color="Algorithm", text_auto='.0f')
        st.plotly_chart(fig4, use_container_width=True)

    st.divider()
    st.markdown("### 📋 종합 성능 요약표")
    st.dataframe(df.style.highlight_min(subset=['Latency (µs)', 'Memory (KB)', 'Trace Size (Cells)'], color='lightgreen')
                          .highlight_max(subset=['Throughput (MB/s)'], color='lightgreen'), 
                 use_container_width=True)

else:
    st.warning("📊 현재 저장된 측정 결과가 없습니다. 상단의 [전체 시스템 벤치마크 실행] 버튼을 눌러 Rust 엔진을 가동해 주세요.")