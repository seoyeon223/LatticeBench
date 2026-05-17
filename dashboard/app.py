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

MEMORY_JSON_PATH = os.path.join(PROJECT_ROOT, "memory_results.json") 
TRACE_JSON_PATH = os.path.join(PROJECT_ROOT, "trace_results.json")

# 🟢 [수정] SWIFFT의 세 가지 버전을 알고리즘 목록에 추가
ALGORITHMS = [
    "SWIFFT-Naive", 
    "SWIFFT-Scalar", 
    "SWIFFT-AVX2", 
    "Keccak", 
    "Poseidon", 
    "SHA-256"
]
INPUT_SIZE_BYTES = 1024  # 1KB 기준

def run_benchmark():
    # st.spinner 대신 st.status를 사용하여 진행 상황을 실시간으로 보여줍니다.
    with st.status("🚀 Rust 코어 엔진에서 전체 벤치마크를 수행 중입니다...", expanded=True) as status:
        
        # ---------------------------------------------------------
        # 1. 속도 벤치마크 (Criterion)
        # ---------------------------------------------------------
        st.write("⏱️ 1/3: 속도 및 처리량 벤치마크 실행 중 (cargo bench)...")
        bench_res = subprocess.run(
            "cargo bench", 
            shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT
        )
        
        if bench_res.returncode != 0:
            status.update(label="❌ 속도 벤치마크 실행 실패", state="error", expanded=True)
            st.code(bench_res.stderr)
            return

        # ---------------------------------------------------------
        # 2. 메모리 벤치마크
        # ---------------------------------------------------------
        st.write("💾 2/3: 메모리 프로파일링 실행 중 (memory_bench)...")
        mem_res = subprocess.run(
            "cargo run --release --bin memory_bench", 
            shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT
        )
        
        if mem_res.returncode != 0:
            status.update(label="❌ 메모리 벤치마크 실행 실패", state="error", expanded=True)
            st.code(mem_res.stderr)
            return

        # ---------------------------------------------------------
        # 3. ZK Trace 벤치마크
        # ---------------------------------------------------------
        st.write("🧩 3/3: 알고리즘별 ZK Trace 생성 및 측정 중...")
        trace_data = {}
        
        # 실행할 Trace 바이너리 목록 (이전에 생성한 prove_bench 포함 가능)
        binaries = {
            "SHA-256": "prove_bench",    
            "Keccak": "trace_keccak",
            "Poseidon": "trace_poseidon2",
            "SWIFFT-AVX2": "trace_swifft"
        }
        
        for algo, bin_name in binaries.items():
            st.write(f"  ▶ {algo} Trace 측정 중 (`{bin_name}`)...")
            res = subprocess.run(
                f"cargo run --release --bin {bin_name}", 
                shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT
            )
            
            # 터미널 출력에서 Trace Size 숫자 추출
            match = re.search(r'Trace Size:\s*(\d+)', res.stdout, re.IGNORECASE)
            if match:
                trace_val = int(match.group(1))
                trace_data[algo] = trace_val
                
                # SWIFFT는 수학적으로 로직(행의 개수)이 같으므로 다른 버전에도 복사
                if "SWIFFT" in algo:
                    trace_data["SWIFFT-Naive"] = trace_val
                    trace_data["SWIFFT-Scalar"] = trace_val
            else:
                st.warning(f"⚠️ {algo}의 Trace Size를 찾을 수 없습니다. (에러 또는 출력 포맷 확인 필요)")

        # 추출한 Trace 데이터를 JSON 파일로 저장
        if trace_data:
            with open(TRACE_JSON_PATH, "w") as f:
                json.dump(trace_data, f, indent=2)
        
        # 완료 상태 업데이트
        status.update(label="🎉 모든 벤치마크 분석 완료!", state="complete", expanded=False)
        
    # 측정 완료 후 화면을 새로고침하여 즉시 그래프에 반영
    st.rerun()

def get_latency(keyword):
    """Criterion estimates.json 로드"""
    if not os.path.exists(CRITERION_DIR):
        return None
        
    benchmark_groups = [f for f in os.listdir(CRITERION_DIR) if os.path.isdir(os.path.join(CRITERION_DIR, f)) and f != "report"]
    
    for group in benchmark_groups:
        group_path = os.path.join(CRITERION_DIR, group)
        folders = [f for f in os.listdir(group_path) if os.path.isdir(os.path.join(group_path, f))]
        
        # 🟢 [수정] 대소문자 및 하이픈(-) 완화된 매칭 로직
        target_folder = next((f for f in folders if keyword.lower() in f.lower()), None)
        
        if target_folder:
            json_path = os.path.join(group_path, target_folder, "new", "estimates.json")
            if os.path.exists(json_path):
                with open(json_path, 'r') as f:
                    data = json.load(f)
                    return data['mean']['point_estimate'] / 1000.0 # ns -> µs
    return None

def get_memory_usage(keyword):
    if not os.path.exists(MEMORY_JSON_PATH): return None
    try:
        with open(MEMORY_JSON_PATH, 'r') as f:
            data = json.load(f)
            return data.get(keyword, None)
    except Exception: return None

def get_trace_size(keyword):
    if not os.path.exists(TRACE_JSON_PATH): return None
    try:
        with open(TRACE_JSON_PATH, 'r') as f:
            data = json.load(f)
            return data.get(keyword, None)
    except Exception: return None

# 실행 버튼
if st.button("🚀 전체 시스템 벤치마크 실행"):
    run_benchmark()

st.divider()

# --- 데이터 수집 ---
results = []
for algo in ALGORITHMS:
    latency = get_latency(algo)
    throughput = (INPUT_SIZE_BYTES / (latency * 1e-6)) / (1024 * 1024) if latency else None
    memory = get_memory_usage(algo)
    trace = get_trace_size(algo)
    
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
    # 알고리즘 순서를 보장하기 위해 카테고리 설정 (그래프 출력 순서 고정)
    df['Algorithm'] = pd.Categorical(df['Algorithm'], categories=ALGORITHMS, ordered=True)
    df = df.sort_values('Algorithm')

    tab1, tab2, tab3, tab4 = st.tabs([
        "⏱️ 실행 시간", "🚀 처리량", "💾 메모리 사용량", "🧩 ZK 트레이스"
    ])
    
    # 공통 차트 설정
    def create_chart(y_col, title, unit, is_higher_better=False):
        color_map = {
            "SWIFFT-Naive": "#FFA07A",   # 주황색 계열
            "SWIFFT-Scalar": "#FF7F50", 
            "SWIFFT-AVX2": "#FF4500",   # 진한 주황 (최적화 강조)
            "Keccak": "#4682B4",
            "Poseidon": "#3CB371",
            "SHA-256": "#808080"
        }
        fig = px.bar(df, x="Algorithm", y=y_col, color="Algorithm", 
                     color_discrete_map=color_map, text_auto='.2f',
                     title=f"{title} ({unit})")
        return fig

    with tab1:
        st.plotly_chart(create_chart("Latency (µs)", "Hash Latency", "µs"), use_container_width=True)
    with tab2:
        st.plotly_chart(create_chart("Throughput (MB/s)", "Data Throughput", "MB/s", True), use_container_width=True)
    with tab3:
        st.plotly_chart(create_chart("Memory (KB)", "Memory Peak Usage", "KB"), use_container_width=True)
    with tab4:
        st.plotly_chart(create_chart("Trace Size (Cells)", "ZK Proof Complexity", "Cells"), use_container_width=True)

    st.divider()
    st.dataframe(df.style.highlight_min(subset=['Latency (µs)', 'Memory (KB)', 'Trace Size (Cells)'], color='lightgreen')
                          .highlight_max(subset=['Throughput (MB/s)'], color='lightgreen'), 
                 use_container_width=True)
else:
    st.warning("📊 측정 결과가 없습니다. 버튼을 눌러주세요.")