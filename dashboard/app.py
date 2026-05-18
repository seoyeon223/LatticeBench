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

# =====================================================================
# ⚠️ 결과 해석 시 반드시 유의할 사항 (측정의 한계)
# =====================================================================
with st.expander("⚠️ 결과 해석 전 필독 — 측정의 한계와 비교 가능 범위", expanded=True):
    st.markdown("""
이 대시보드의 수치는 **그대로 "어느 해시가 더 우수하다"로 읽으면 안 됩니다.**
측정 대상마다 성격이 다르기 때문입니다. 아래를 전제로 해석하세요.

**1. SHA-256 트레이스는 완전한 회로가 아닙니다 (합성 벤치).**
"SHA-256-style bitwise circuit" 항목의 ZK 트레이스/메모리는 비트 분해·
부울·단일 XOR 제약만 포함하는 *합성 트레이스* 기준이며, SHA-256 압축
함수의 핵심 구성요소(모듈러 덧셈·Σ/σ 회전·Ch/Maj·메시지 스케줄)가
**빠져 있습니다.** Keccak/Poseidon2(완전 회로)와의 직접 비교는 알고리즘
차이가 아니라 구현 충실도 차이를 반영합니다.

**2. 메모리는 회로별 '최소 요구 config'에서 측정됩니다 (절대 비교 금지).**
ZK 회로는 제약 차수에 따라 필요한 최소 FRI blowup 이 다릅니다.
SWIFFT 통합 AIR 는 제약 차수 3 으로 `log_blowup=2` 가 **필수**(낮추면
검증 불가)이고 trace 자연 크기가 2^15 입니다. 반면 SHA/Keccak/Poseidon2
는 차수가 낮아 `log_blowup=1` + 2^14 로 통일했습니다. 따라서 SWIFFT
메모리를 타 알고리즘과 **절대값으로 직접 비교하면 안 됩니다.** 아래
표/그래프의 SWIFFT 메모리에는 config 보정 안내가 자동 표기됩니다.

**3. 네이티브 속도 vs ZK 비용은 상충하는 축입니다.**
Poseidon2 는 네이티브 처리량 최하위지만 회로/메모리에서는 효율적입니다.
"처리량" 탭만 보고 판단하지 말고 "ZK 트레이스"·"메모리" 탭을 함께
보십시오.

**4. Poseidon2 처리량(MB/s)은 참고값입니다.**
Poseidon2 는 바이트가 아닌 필드 원소를 처리합니다. MB/s 는 공통 입력
바이트열을 환산한 근사 참고값이며 바이트 해시와 직접 비교 대상이
아닙니다.

**5. SWIFFT 3종의 트레이스/메모리는 동일 회로 기준 공통값입니다.**
Naive/Scalar/AVX2 는 네이티브 *구현*이 다르지만 ZK *회로(AIR)*는
동일합니다. 속도는 구현별 실측, 트레이스·메모리는 동일 AIR 의 공통값.

**6. 메모리 지표 정의:** "trace 생성 + STARK 증명 생성 전체
워크플로우의 peak 힙(dhat max_bytes)". 순수 prove 만 분리한 값이
아니며, ZK 에서 실제 메모리 병목 단위(trace+증명 합산)와 일치합니다.

**7. 측정 환경 고정.** 모든 ZK 측정은 단일 Plonky3 리비전(`64b3cc0`)
및 BabyBear 필드 기준입니다.

**정당하게 도출 가능한 결론:** 각 함수의 워크로드 대비 스케일링 특성,
동일 성격 그룹 내 비교(SWIFFT 3종 속도, 완전 회로 Keccak↔Poseidon2),
그리고 *config 보정 후* 메모리 상대 해석.
""")

# --- 경로 설정 ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
CRITERION_DIR = os.path.join(PROJECT_ROOT, "target", "criterion")

MEMORY_JSON_PATH = os.path.join(PROJECT_ROOT, "memory_results.json")
TRACE_JSON_PATH = os.path.join(PROJECT_ROOT, "trace_results.json")

# =====================================================================
# 단일 표준 키 집합 — 모든 곳에서 이 키를 사용 (불일치 버그 방지)
# =====================================================================
ALGORITHMS = [
    "SWIFFT-Naive",
    "SWIFFT-Scalar",
    "SWIFFT-AVX2",
    "Keccak",
    "Poseidon2",
    "SHA-256-style bitwise circuit",
]

CRITERION_KEYWORD = {
    "SWIFFT-Naive": "SWIFFT-Naive",
    "SWIFFT-Scalar": "SWIFFT-Scalar",
    "SWIFFT-AVX2": "SWIFFT-AVX2",
    "Keccak": "Keccak",
    "Poseidon2": "Poseidon2",
    "SHA-256-style bitwise circuit": "SHA-256",
}

# 메모리 측정 config (각 mem_prove_* / trace_swifft 가 쓴 실제 값).
# 절대 비교 방지를 위해 대시보드가 명시적으로 표기.
MEM_CONFIG = {
    "SWIFFT-Naive": {"log_blowup": 2, "height": 32768},
    "SWIFFT-Scalar": {"log_blowup": 2, "height": 32768},
    "SWIFFT-AVX2": {"log_blowup": 2, "height": 32768},
    "Keccak": {"log_blowup": 1, "height": 16384},
    "Poseidon2": {"log_blowup": 1, "height": 16384},
    "SHA-256-style bitwise circuit": {"log_blowup": 1, "height": 16384},
}

INPUT_SIZE_BYTES = 1024


def run_benchmark():
    with st.status("🚀 Rust 코어 엔진에서 전체 벤치마크를 수행 중입니다...", expanded=True) as status:

        st.write("⏱️ 1/3: 속도 및 처리량 벤치마크 실행 중 (cargo bench)...")
        bench_res = subprocess.run(
            "cargo bench --bench hash_bench",
            shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT
        )
        if bench_res.returncode != 0:
            status.update(label="❌ 속도 벤치마크 실행 실패", state="error", expanded=True)
            st.code(bench_res.stderr)
            return

        # ── 2. 메모리: prove peak (4개 알고리즘 각각 별도 바이너리) ──
        st.write("💾 2/3: STARK 증명 peak 메모리 측정 중...")
        mem_bins = {
            "SHA-256-style bitwise circuit": "mem_prove_sha256",
            "Keccak": "mem_prove_keccak",
            "Poseidon2": "mem_prove_poseidon2",
            "SWIFFT (3종 공통)": "trace_swifft",
        }
        for label, bin_name in mem_bins.items():
            st.write(f"  ▶ {label} prove 메모리 측정 중 (`{bin_name}`)...")
            r = subprocess.run(
                f"cargo run --release --bin {bin_name}",
                shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT
            )
            if r.returncode != 0:
                st.warning(f"⚠️ {label} 메모리 측정 실패 (`{bin_name}`). stderr 일부:")
                st.code(r.stderr[-1500:])
            # 각 바이너리가 memory_results.json 을 부분 갱신 (키 보존)

        # ── 3. ZK Trace ──
        st.write("🧩 3/3: 알고리즘별 ZK Trace 생성 및 측정 중...")
        trace_data = {}
        trace_bins = {
            "SHA-256-style bitwise circuit": "trace_sha256",
            "Keccak": "trace_keccak",
            "Poseidon2": "trace_poseidon2",
            "SWIFFT-AVX2": "trace_swifft",
        }
        for algo, bin_name in trace_bins.items():
            st.write(f"  ▶ {algo} Trace 측정 중 (`{bin_name}`)...")
            res = subprocess.run(
                f"cargo run --release --bin {bin_name}",
                shell=True, capture_output=True, text=True, cwd=PROJECT_ROOT
            )
            match = re.search(r'Trace Size[^:]*:\s*(\d+)', res.stdout, re.IGNORECASE)
            if match:
                trace_val = int(match.group(1))
                trace_data[algo] = trace_val
                if "SWIFFT" in algo:
                    trace_data["SWIFFT-Naive"] = trace_val
                    trace_data["SWIFFT-Scalar"] = trace_val
                    trace_data["SWIFFT-AVX2"] = trace_val
            else:
                st.warning(
                    f"⚠️ {algo} Trace Size 추출 실패 (`cargo run --release "
                    f"--bin {bin_name}` 출력 확인 필요)"
                )

        if trace_data:
            with open(TRACE_JSON_PATH, "w") as f:
                json.dump(trace_data, f, indent=2)

        status.update(label="🎉 모든 벤치마크 분석 완료!", state="complete", expanded=False)

    st.rerun()


def get_latency(algo_key):
    if not os.path.exists(CRITERION_DIR):
        return None
    keyword = CRITERION_KEYWORD.get(algo_key, algo_key)
    groups = [
        f for f in os.listdir(CRITERION_DIR)
        if os.path.isdir(os.path.join(CRITERION_DIR, f)) and f != "report"
    ]
    for group in groups:
        gp = os.path.join(CRITERION_DIR, group)
        folders = [
            f for f in os.listdir(gp) if os.path.isdir(os.path.join(gp, f))
        ]
        tgt = next((f for f in folders if keyword.lower() in f.lower()), None)
        if tgt:
            jp = os.path.join(gp, tgt, "new", "estimates.json")
            if os.path.exists(jp):
                with open(jp, 'r') as f:
                    return json.load(f)['mean']['point_estimate'] / 1000.0
    return None


def load_memory_json():
    if not os.path.exists(MEMORY_JSON_PATH):
        return {}
    try:
        with open(MEMORY_JSON_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def get_trace_size(keyword):
    if not os.path.exists(TRACE_JSON_PATH):
        return None
    try:
        with open(TRACE_JSON_PATH, 'r') as f:
            return json.load(f).get(keyword, None)
    except Exception:
        return None


if st.button("🚀 전체 시스템 벤치마크 실행"):
    run_benchmark()

st.divider()

mem_json = load_memory_json()

# --- 데이터 수집 ---
results = []
for algo in ALGORITHMS:
    latency = get_latency(algo)
    throughput = (INPUT_SIZE_BYTES / (latency * 1e-6)) / (1024 * 1024) if latency else None
    memory = mem_json.get(algo, None)  # KB (mem_prove_* 가 표준 키로 저장)
    trace = get_trace_size(algo)

    cfg = MEM_CONFIG.get(algo, {})
    mem_note = ""
    if memory is not None and cfg:
        mem_note = f"blowup={cfg['log_blowup']}, h={cfg['height']}"

    if any(v is not None for v in [latency, memory, trace]):
        results.append({
            "Algorithm": algo,
            "Latency (µs)": latency if latency else 0,
            "Throughput (MB/s)": throughput if throughput else 0,
            "Memory (MB)": (memory / 1024.0) if memory else 0,  # KB→MB
            "Mem config": mem_note,
            "Trace Size (Cells)": trace if trace else 0,
        })

df = pd.DataFrame(results)

if not df.empty:
    df['Algorithm'] = pd.Categorical(df['Algorithm'], categories=ALGORITHMS, ordered=True)
    df = df.sort_values('Algorithm')

    tab1, tab2, tab3, tab4 = st.tabs([
        "⏱️ 실행 시간", "🚀 처리량", "💾 증명 메모리", "🧩 ZK 트레이스"
    ])

    COLOR_MAP = {
        "SWIFFT-Naive": "#FFA07A",
        "SWIFFT-Scalar": "#FF7F50",
        "SWIFFT-AVX2": "#FF4500",
        "Keccak": "#4682B4",
        "Poseidon2": "#3CB371",
        "SHA-256-style bitwise circuit": "#808080",
    }

    def create_chart(y_col, title, unit):
        return px.bar(
            df, x="Algorithm", y=y_col, color="Algorithm",
            color_discrete_map=COLOR_MAP, text_auto='.2f',
            title=f"{title} ({unit})"
        )

    with tab1:
        st.plotly_chart(create_chart("Latency (µs)", "Hash Latency", "µs"),
                        use_container_width=True)
        st.caption("⚠️ 네이티브 CPU 실행 시간. ZK 회로 비용과 무관한 별개 지표입니다.")
    with tab2:
        st.plotly_chart(create_chart("Throughput (MB/s)", "Data Throughput", "MB/s"),
                        use_container_width=True)
        st.caption("⚠️ Poseidon2는 필드 원소를 처리하므로 MB/s는 참고값이며 "
                   "바이트 해시와 직접 비교 대상이 아닙니다.")
    with tab3:
        st.plotly_chart(create_chart("Memory (MB)", "STARK Prove Peak Memory", "MB"),
                        use_container_width=True)
        st.error(
            "⚠️ **절대 비교 금지.** SWIFFT 는 제약 차수 3 때문에 "
            "`log_blowup=2`(필수) + height 2^15 기준이고, SHA/Keccak/"
            "Poseidon2 는 `log_blowup=1` + 2^14 기준입니다. SWIFFT 막대는 "
            "config 만으로 약 3.6배 부풀려져 있어 타 알고리즘과 직접 "
            "비교하면 안 됩니다. 표의 'Mem config' 열에 각 측정 조건이 "
            "표기되어 있으니 config 보정 후 상대 해석만 하십시오."
        )
        # config 보정 추정치 (SHA 기준선으로 환산) — 참고용
        st.markdown("**참고: config 보정 추정 (SHA 기준 blowup=1, 2^14 환산)**")
        adj_rows = []
        for _, r in df.iterrows():
            cfg = MEM_CONFIG.get(r["Algorithm"], {})
            if r["Memory (MB)"] > 0 and cfg:
                # blowup 2→1 ≈ /2, height 2^15→2^14 ≈ /2  (근사)
                factor = 1.0
                if cfg.get("log_blowup") == 2:
                    factor *= 2.0
                if cfg.get("height") == 32768:
                    factor *= 2.0
                adj_rows.append({
                    "Algorithm": r["Algorithm"],
                    "측정 Memory (MB)": round(r["Memory (MB)"], 1),
                    "보정계수(÷)": factor,
                    "보정 추정 Memory (MB)": round(r["Memory (MB)"] / factor, 1),
                    "Mem config": r["Mem config"],
                })
        if adj_rows:
            st.dataframe(pd.DataFrame(adj_rows), use_container_width=True)
            st.caption("보정은 blowup·height 차이를 ÷2씩 적용한 *근사*입니다. "
                       "정확한 보정이 아니라 '같은 조건이었다면 대략 어느 "
                       "수준인지'를 가늠하는 참고용입니다. 리포트에는 측정값과 "
                       "config 를 함께 보고하고, 보정치는 보조로만 쓰십시오.")
    with tab4:
        st.plotly_chart(create_chart("Trace Size (Cells)", "ZK Proof Complexity", "Cells"),
                        use_container_width=True)
        st.caption("⚠️ 'SHA-256-style bitwise circuit'은 완전한 SHA-256 회로가 "
                   "아닌 합성 트레이스입니다. SWIFFT 3종은 동일 회로 공통값입니다.")

    st.divider()
    show_cols = [
        "Algorithm", "Latency (µs)", "Throughput (MB/s)",
        "Memory (MB)", "Mem config", "Trace Size (Cells)"
    ]
    st.dataframe(
        df[show_cols].style
          .highlight_min(subset=['Latency (µs)', 'Trace Size (Cells)'],
                         color='lightgreen')
          .highlight_max(subset=['Throughput (MB/s)'], color='lightgreen'),
        use_container_width=True
    )
    st.caption("녹색 강조는 단순 최소/최대이며 측정 한계를 고려하지 않은 "
               "표시입니다. **Memory (MB) 는 config 가 알고리즘마다 달라 "
               "최소값 강조를 의도적으로 제외했습니다** ('Mem config' 열 참조). "
               "Trace Size 최소 강조도 합성 SHA-256 때문에 오해 소지가 "
               "있으니 주의하십시오.")
else:
    st.warning("📊 측정 결과가 없습니다. 버튼을 눌러주세요.")