#!/bin/bash

BUILD_DIR=./target

# 처음 테스트 시작 시간 기준 디렉터리 (환경변수나 임시파일로 고정)
if [ -z "$START_TS" ]; then
    if [ -f ".start_time" ]; then
        START_TS=$(cat .start_time)
    else
        START_TS=$(date "+%Y%m%d_%H%M%S")
        echo "$START_TS" > .start_time
    fi
fi

ROOT_DIR=./coverage_result/$START_TS
LOG_DIR=${ROOT_DIR}/info_logs
HTML_DIR=${ROOT_DIR}/html_reports
SUMMARY_LOG=${ROOT_DIR}/coverage_summary.log
LCOV_BASE=${BUILD_DIR}/coverage_base.info

mkdir -p "$LOG_DIR"
mkdir -p "$HTML_DIR"


INDEX=$(ls "$LOG_DIR"/coverage_test_*.info 2>/dev/null | wc -l)
TS=$(printf "%08d" $INDEX)

echo "[*] Collecting coverage at $TS"

RAW_INFO=${LOG_DIR}/coverage_test_${TS}.info
CUR_TOTAL=${LOG_DIR}/coverage_total.info

# 원시 수집
lcov --capture --rc lcov_branch_coverage=1 \
    --directory "$BUILD_DIR" \
    --output-file "$RAW_INFO"

# 병합: base + 새로운 raw 만으로 구성
lcov --rc lcov_branch_coverage=1 \
    --add-tracefile "$LCOV_BASE" \
    --add-tracefile "$RAW_INFO" \
    --output-file "$CUR_TOTAL"

# 요약 누적 기록
{
    echo -e "\n--- Coverage Summary @ ${TS} ---"
    lcov --summary "$CUR_TOTAL"
} >> "$SUMMARY_LOG"

echo "[+] Raw  coverage: $RAW_INFO"
echo "[+] Total coverage: $CUR_TOTAL"
echo "[+] Summary updated: $SUMMARY_LOG"

