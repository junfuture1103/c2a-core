#!/bin/bash
#[NOTICE] You have to change cFS/ path in merged.info appropriately

# 스크립트 위치로 이동
cd "$(dirname "$0")"

# 현재 시간 가져오기 (형식: YYYYMMDD_HHMMSS)
timestamp=$(date +"%Y%m%d_%H%M%S")

# 출력 디렉토리 설정
output_dir="./coverage_result/html_reports_${timestamp}"

# genhtml 실행
genhtml ./coverage_result/20251121_082803/info_logs/merged.info \
  --output-directory "$output_dir" \
  --title "Coverage Report 20251121_082803" \
  --show-details \
  --highlight \
  --legend \
  --rc genhtml_branch_coverage=1
