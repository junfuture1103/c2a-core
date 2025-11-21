#!/bin/bash

cd ./coverage_result/20251121_082803/info_logs

# 초기 병합 대상: 첫 번째 파일
info_files=(coverage_test_*.info)
merged_file="merged.info"

cp "${info_files[0]}" "$merged_file"

# 병합 로그 저장
log_file="coverage_log.txt"
echo "" > "$log_file"

# 나머지 파일들 순차 병합
for ((i=0; i<${#info_files[@]}; i++)); do
    lcov -a "$merged_file" -a "${info_files[i]}" -o temp_merged.info --rc lcov_branch_coverage=1 | tee -a "$log_file"
    mv temp_merged.info "$merged_file"
done
