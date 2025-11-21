#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
퍼징을 위한 모든 커맨드 자동 전송 스크립트

이 스크립트는:
1. Cmd DB CSV에서 모든 명령과 파라미터 정보를 자동으로 파싱
2. c2a_enum에서 모든 명령 코드를 가져옴
3. 파라미터 타입에 따라 랜덤 값 생성
4. 모든 명령을 자동으로 전송
"""

import os
import sys
import csv
import random
import re
import json
import datetime
from pathlib import Path

import isslwings as wings
import pytest

ROOT_PATH = "../../"
sys.path.append(os.path.dirname(__file__) + "/" + ROOT_PATH + "utils")
sys.path.append(os.path.dirname(__file__))
import c2a_enum_utils
import wings_utils
from fuzzing_helper import (
    CommandDBParser,
    FuzzingParamGenerator,
    generate_params_from_cmd_info,
    get_all_cmd_codes_from_enum
)

c2a_enum = c2a_enum_utils.get_c2a_enum()
ope = wings_utils.get_wings_operation()

# Cmd DB CSV 경로
CMD_DB_CSV_PATH = os.path.dirname(__file__) + "/" + ROOT_PATH + "/../../../tlm-cmd-db/CMD_DB/SAMPLE_MOBC_CMD_DB_CMD_DB.csv"


# 함수들은 fuzzing_helper 모듈에서 import됨


def get_command_dispatcher_log(cdis_idx=0):
    """
    Command Dispatcher 텔레메트리에서 명령 실행 로그 가져오기
    
    Args:
        cdis_idx: CDIS 인덱스 (0: GS Command Dispatcher)
    
    Returns:
        dict: CDIS 로그 정보
    """
    try:
        # CDIS 텔레메트리 생성
        wings.util.send_rt_cmd_and_confirm(
            ope, c2a_enum.Cmd_CODE_CDIS_MGR_SET_IDX_FOR_TLM, (cdis_idx,), c2a_enum.Tlm_CODE_HK
        )
        tlm_CDIS = wings.util.generate_and_receive_tlm(
            ope, c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM, c2a_enum.Tlm_CODE_CDIS
        )
        
        return {
            'prev_cmd_code': tlm_CDIS.get("CDIS.PREV.CODE", 0),
            'prev_exec_sts': tlm_CDIS.get("CDIS.PREV.CMD_RET.EXEC_STS", 0),
            'prev_err_code': tlm_CDIS.get("CDIS.PREV.CMD_RET.ERR_CODE", 0),
            'prev_time': tlm_CDIS.get("CDIS.PREV.TIME.TOTAL_CYCLE", 0),
            'prev_err_cmd_code': tlm_CDIS.get("CDIS.PREV_ERR.CODE", 0),
            'prev_err_exec_sts': tlm_CDIS.get("CDIS.PREV_ERR.CMD_RET.EXEC_STS", 0),
            'error_counter': tlm_CDIS.get("CDIS.ERROR_COUNTER", 0),
            'lockout': tlm_CDIS.get("CDIS.LOCKOUT", 0),
        }
    except Exception as e:
        print(f"Error getting CDIS log: {e}")
        return None


def get_event_logger_log():
    """
    Event Logger 텔레메트리에서 이벤트 로그 가져오기
    
    Returns:
        dict: Event Logger 로그 정보
    """
    try:
        # EL 기본 텔레메트리
        tlm_EL = wings.util.generate_and_receive_tlm(
            ope, c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM, c2a_enum.Tlm_CODE_EL
        )
        
        # TLog 텔레메트리 (최근 이벤트)
        tlm_EL_TLOG = None
        try:
            tlm_EL_TLOG = wings.util.generate_and_receive_tlm(
                ope, c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM, c2a_enum.Tlm_CODE_EL_TLOG
            )
        except:
            pass
        
        return {
            'latest_event': {
                'group': tlm_EL.get("EL.LATEST_EVENT.GROUP", 0),
                'local': tlm_EL.get("EL.LATEST_EVENT.LOCAL", 0),
                'err_level': tlm_EL.get("EL.LATEST_EVENT.ERR_LEVEL", 0),
                'total_cycle': tlm_EL.get("EL.LATEST_EVENT.TIME.TOTAL_CYCLE", 0),
                'note': tlm_EL.get("EL.LATEST_EVENT.NOTE", 0),
            },
            'statistics': {
                'record_counter_total': tlm_EL.get("EL.STATISTICS.RECORD_COUNTER_TOTAL", 0),
                'record_counters_high': tlm_EL.get("EL.STATISTICS.RECORD_COUNTERS_HIGH", 0),
                'record_counters_low': tlm_EL.get("EL.STATISTICS.RECORD_COUNTERS_LOW", 0),
            },
            'tlog': tlm_EL_TLOG,
        }
    except Exception as e:
        print(f"Error getting EL log: {e}")
        return None


def send_command_rt(cmd_name, cmd_code, params, collect_logs=True):
    """
    Realtime Command로 명령 전송 및 로그 수집
    
    Args:
        collect_logs: 로그 수집 여부
    
    Returns:
        tuple: (실행 결과, 로그 정보)
    """
    logs = {}
    
    try:
        result = wings.util.send_rt_cmd_and_confirm(
            ope, cmd_code, params, c2a_enum.Tlm_CODE_HK
        )
        
        if collect_logs:
            # 명령 실행 후 로그 수집
            logs['cdis'] = get_command_dispatcher_log(0)  # GS Command Dispatcher
            logs['el'] = get_event_logger_log()
        
        return result, logs
    except Exception as e:
        print(f"Error sending {cmd_name}: {e}")
        return "ERR", logs


def send_command_tl(cmd_name, cmd_code, params, ti_offset=10000):
    """
    Timeline Command로 명령 전송
    
    Args:
        ti_offset: 현재 TI로부터의 오프셋
    """
    try:
        # 현재 TI 가져오기 (HK 텔레메트리에서)
        tlm_HK = wings.util.generate_and_receive_tlm(
            ope, c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM, c2a_enum.Tlm_CODE_HK
        )
        current_ti = tlm_HK.get("HK.SH.TI", 0)
        future_ti = current_ti + ti_offset
        
        wings.util.send_tl_cmd(ope, future_ti, cmd_code, params)
        return "SUC"
    except Exception as e:
        print(f"Error sending TL {cmd_name}: {e}")
        return "ERR"


def send_command_bl(cmd_name, cmd_code, params, ti_offset=10000):
    """
    Block Command로 명령 전송
    """
    try:
        # 현재 TI 가져오기
        tlm_HK = wings.util.generate_and_receive_tlm(
            ope, c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM, c2a_enum.Tlm_CODE_HK
        )
        current_ti = tlm_HK.get("HK.SH.TI", 0)
        future_ti = current_ti + ti_offset
        
        ope.send_bl_cmd(future_ti, cmd_code, params)
        return "SUC"
    except Exception as e:
        print(f"Error sending BL {cmd_name}: {e}")
        return "ERR"


@pytest.mark.real
@pytest.mark.sils
def test_fuzz_all_commands_rt(strategy="random", max_commands=None, save_logs=True):
    """
    모든 명령을 Realtime Command로 퍼징 및 로그 수집
    
    Args:
        strategy: "random", "min", "max", "edge" 중 하나
        max_commands: 최대 테스트할 명령 수 (None이면 전체)
        save_logs: 로그를 파일로 저장할지 여부
    """
    print(f"\n=== Realtime Command 퍼징 시작 (strategy: {strategy}) ===")
    
    # 명령 정보 로드
    cmd_db_parser = CommandDBParser(CMD_DB_CSV_PATH)
    enum_cmd_codes = get_all_cmd_codes_from_enum(c2a_enum)
    param_generator = FuzzingParamGenerator(strategy=strategy)
    
    results = {
        "SUC": 0,
        "PRM": 0,
        "CNT": 0,
        "ROE": 0,
        "ERR": 0,
        "SKIP": 0
    }
    
    tested_commands = []
    fuzzing_logs = []
    
    # 로그 저장 디렉토리 생성
    if save_logs:
        log_dir = Path(__file__).parent / "fuzzing_logs"
        log_dir.mkdir(exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"fuzzing_log_{timestamp}.json"
    
    # 명령 리스트 준비
    commands_to_test = list(enum_cmd_codes.items())
    if max_commands:
        commands_to_test = commands_to_test[:max_commands]
    
    # 모든 명령 테스트
    for cmd_name, cmd_code in commands_to_test:
        # Cmd DB에서 정보 가져오기
        cmd_info = cmd_db_parser.get_command_info(cmd_name)
        
        if cmd_info is None:
            # Cmd DB에 없으면 기본값 사용
            cmd_info = {
                'code': cmd_code,
                'num_params': 0,
                'param_types': [],
                'param_descriptions': [],
                'description': '',
                'danger_flag': False
            }
        
        # 파라미터 생성
        params = generate_params_from_cmd_info(cmd_info, param_generator)
        
        # 명령 전송 및 로그 수집
        print(f"Testing RT: {cmd_name} (0x{cmd_code:04X}) with params: {params}")
        try:
            result, logs = send_command_rt(cmd_name, cmd_code, params, collect_logs=save_logs)
        except Exception as e:
            print(f"  Exception: {e}")
            result = "ERR"
            logs = {}
        
        results[result] = results.get(result, 0) + 1
        tested_commands.append((cmd_name, cmd_code, params, result))
        
        # 로그 저장
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cmd_name': cmd_name,
            'cmd_code': f"0x{cmd_code:04X}",
            'params': params,
            'result': result,
            'logs': logs
        }
        fuzzing_logs.append(log_entry)
        
        # 결과 출력
        print(f"  Result: {result}")
        if logs.get('cdis'):
            cdis_log = logs['cdis']
            if cdis_log.get('prev_exec_sts') != 0:  # 0 = SUCCESS
                print(f"    CDIS Exec Status: {cdis_log.get('prev_exec_sts')}, "
                      f"Err Code: {cdis_log.get('prev_err_code')}")
        if logs.get('el') and logs['el'].get('latest_event'):
            latest = logs['el']['latest_event']
            if latest.get('group') != 0:
                print(f"    Latest Event: Group={latest.get('group')}, "
                      f"Local={latest.get('local')}, Level={latest.get('err_level')}")
    
    # 결과 요약
    print("\n=== 퍼징 결과 요약 ===")
    print(f"총 테스트한 명령 수: {len(tested_commands)}")
    for result_type, count in results.items():
        if count > 0:
            print(f"  {result_type}: {count}")
    
    # 실패한 명령 출력
    failed_commands = [cmd for cmd in tested_commands if cmd[3] not in ["SUC", "PRM"]]
    if failed_commands:
        print("\n=== 실패한 명령 목록 ===")
        for cmd_name, cmd_code, params, result in failed_commands:
            print(f"  {cmd_name} (0x{cmd_code:04X}): {result}")
    
    # 로그 파일 저장
    if save_logs and fuzzing_logs:
        log_data = {
            'fuzzing_info': {
                'strategy': strategy,
                'total_commands': len(tested_commands),
                'timestamp': timestamp,
                'results': results
            },
            'commands': fuzzing_logs
        }
        
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n=== 로그 저장 완료 ===")
        print(f"로그 파일: {log_file}")
        print(f"총 로그 엔트리: {len(fuzzing_logs)}")


@pytest.mark.real
@pytest.mark.sils
def test_fuzz_all_commands_tl():
    """
    모든 명령을 Timeline Command로 퍼징
    """
    print("\n=== Timeline Command 퍼징 시작 ===")
    
    cmd_db_commands = parse_cmd_db_csv(CMD_DB_CSV_PATH)
    enum_cmd_codes = get_all_cmd_codes_from_enum()
    
    results = {"SUC": 0, "ERR": 0}
    
    # 샘플 명령만 테스트 (전체는 시간이 오래 걸림)
    sample_commands = list(enum_cmd_codes.items())[:10]  # 처음 10개만
    
    for cmd_name, cmd_code in sample_commands:
        if cmd_name in cmd_db_commands:
            cmd_info = cmd_db_commands[cmd_name]
        else:
            cmd_info = CommandInfo()
            cmd_info.name = cmd_name
            cmd_info.code = cmd_code
        
        params = generate_params_for_cmd(cmd_info)
        
        print(f"Testing TL: {cmd_name} (0x{cmd_code:04X})")
        result = send_command_tl(cmd_name, cmd_code, params)
        results[result] = results.get(result, 0) + 1
    
    print(f"\nTL 퍼징 결과: {results}")


def get_command_info_from_db(cmd_name):
    """
    Cmd DB에서 특정 명령의 정보를 가져옴 (유틸리티 함수)
    """
    cmd_db_commands = parse_cmd_db_csv(CMD_DB_CSV_PATH)
    return cmd_db_commands.get(cmd_name)


def list_all_commands():
    """
    모든 명령 목록과 파라미터 정보를 출력 (디버깅용)
    """
    cmd_db_parser = CommandDBParser(CMD_DB_CSV_PATH)
    enum_cmd_codes = get_all_cmd_codes_from_enum(c2a_enum)
    
    print(f"\n=== 명령 목록 (총 {len(enum_cmd_codes)}개) ===\n")
    
    for cmd_name, cmd_code in sorted(enum_cmd_codes.items()):
        cmd_info = cmd_db_parser.get_command_info(cmd_name)
        if cmd_info:
            print(f"{cmd_name} (0x{cmd_code:04X}):")
            print(f"  Params: {cmd_info['num_params']}")
            print(f"  Description: {cmd_info['description']}")
            if cmd_info['danger_flag']:
                print(f"  [DANGER]")
            for i in range(cmd_info['num_params']):
                param_type = cmd_info['param_types'][i] if i < len(cmd_info['param_types']) else "unknown"
                param_desc = cmd_info['param_descriptions'][i] if i < len(cmd_info['param_descriptions']) else ""
                print(f"    [{i}] {param_type}: {param_desc}")
        else:
            print(f"{cmd_name} (0x{cmd_code:04X}): [Cmd DB에 없음]")


def analyze_fuzzing_log(log_file_path):
    """
    퍼징 로그 파일을 분석하여 통계 및 패턴 출력
    
    Args:
        log_file_path: 로그 파일 경로
    """
    with open(log_file_path, 'r', encoding='utf-8') as f:
        log_data = json.load(f)
    
    print(f"\n=== 퍼징 로그 분석: {log_file_path} ===\n")
    
    fuzzing_info = log_data.get('fuzzing_info', {})
    print(f"전략: {fuzzing_info.get('strategy')}")
    print(f"총 명령 수: {fuzzing_info.get('total_commands')}")
    print(f"타임스탬프: {fuzzing_info.get('timestamp')}")
    print(f"\n결과 요약:")
    for result, count in fuzzing_info.get('results', {}).items():
        if count > 0:
            print(f"  {result}: {count}")
    
    # 에러가 발생한 명령 분석
    commands = log_data.get('commands', [])
    error_commands = [cmd for cmd in commands if cmd.get('result') not in ['SUC', 'PRM']]
    
    if error_commands:
        print(f"\n=== 에러 발생 명령 ({len(error_commands)}개) ===")
        for cmd in error_commands[:10]:  # 최대 10개만 출력
            print(f"\n{cmd.get('cmd_name')} (0x{cmd.get('cmd_code')}):")
            print(f"  Result: {cmd.get('result')}")
            if cmd.get('logs', {}).get('cdis'):
                cdis = cmd['logs']['cdis']
                print(f"  Exec Status: {cdis.get('prev_exec_sts')}")
                print(f"  Err Code: {cdis.get('prev_err_code')}")
            if cmd.get('logs', {}).get('el', {}).get('latest_event'):
                event = cmd['logs']['el']['latest_event']
                if event.get('group') != 0:
                    print(f"  Event: Group={event.get('group')}, Local={event.get('local')}")
    
    # Event Logger 통계
    print(f"\n=== Event Logger 통계 ===")
    total_events = 0
    event_groups = {}
    for cmd in commands:
        if cmd.get('logs', {}).get('el', {}).get('latest_event'):
            event = cmd['logs']['el']['latest_event']
            if event.get('group') != 0:
                total_events += 1
                group = event.get('group')
                event_groups[group] = event_groups.get(group, 0) + 1
    
    print(f"총 이벤트 수: {total_events}")
    print(f"이벤트 그룹별 통계:")
    for group, count in sorted(event_groups.items()):
        print(f"  Group {group}: {count}개")

def send_fin_packet():
    # Actually using modifed nop
    wings.util.send_rt_cmd_and_confirm(
        ope, c2a_enum.Cmd_CODE_NOP, (), c2a_enum.Tlm_CODE_HK
    )


if __name__ == "__main__":
    # 직접 실행 시 명령 목록 출력
    # list_all_commands()
    # test_fuzz_all_commands_rt(max_commands = 1)
    test_fuzz_all_commands_rt()
    
    send_fin_packet()
    # 로그 파일 분석 예제
    # log_file = Path(__file__).parent / "fuzzing_logs" / "fuzzing_log_20240101_120000.json"
    # if log_file.exists():
    #     analyze_fuzzing_log(log_file)

