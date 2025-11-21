#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
퍼징 헬퍼 유틸리티

커맨드 파라미터를 자동으로 생성하고 전송하는 유틸리티 함수들
"""

import csv
import random
import struct
import os


class FuzzingParamGenerator:
    """퍼징용 파라미터 생성기"""
    
    def __init__(self, strategy="random"):
        """
        Args:
            strategy: "random", "min", "max", "edge" 중 하나
        """
        self.strategy = strategy
    
    def generate_value(self, param_type, param_desc=""):
        """
        파라미터 타입에 따라 값을 생성
        
        Args:
            param_type: 파라미터 타입 문자열
            param_desc: 파라미터 설명 (범위 추출에 사용)
        
        Returns:
            생성된 값
        """
        param_type = param_type.lower().strip()
        
        if self.strategy == "random":
            return self._generate_random(param_type, param_desc)
        elif self.strategy == "min":
            return self._generate_min(param_type)
        elif self.strategy == "max":
            return self._generate_max(param_type)
        elif self.strategy == "edge":
            return self._generate_edge(param_type)
        else:
            return self._generate_random(param_type, param_desc)
    
    def _generate_random(self, param_type, param_desc):
        """랜덤 값 생성"""
        if 'uint8_t' in param_type:
            return random.randint(0, 255)
        elif 'int8_t' in param_type:
            return random.randint(-128, 127)
        elif 'uint16_t' in param_type:
            return random.randint(0, 65535)
        elif 'int16_t' in param_type:
            return random.randint(-32768, 32767)
        elif 'uint32_t' in param_type:
            return random.randint(0, 2**31 - 1)
        elif 'int32_t' in param_type:
            return random.randint(-2**31, 2**31 - 1)
        elif 'double' in param_type:
            return random.uniform(-1e10, 1e10)
        elif 'float' in param_type:
            return random.uniform(-1e6, 1e6)
        elif 'raw' in param_type:
            # RAW는 4바이트 랜덤 데이터
            return "0x" + ''.join([f'{random.randint(0, 255):02x}' for _ in range(4)])
        else:
            return random.randint(0, 255)
    
    def _generate_min(self, param_type):
        """최소값 생성"""
        if 'uint' in param_type:
            return 0
        elif 'int8_t' in param_type:
            return -128
        elif 'int16_t' in param_type:
            return -32768
        elif 'int32_t' in param_type:
            return -2**31
        elif 'double' in param_type or 'float' in param_type:
            return -1e10
        else:
            return 0
    
    def _generate_max(self, param_type):
        """최대값 생성"""
        if 'uint8_t' in param_type:
            return 255
        elif 'uint16_t' in param_type:
            return 65535
        elif 'uint32_t' in param_type:
            return 2**31 - 1
        elif 'int8_t' in param_type:
            return 127
        elif 'int16_t' in param_type:
            return 32767
        elif 'int32_t' in param_type:
            return 2**31 - 1
        elif 'double' in param_type or 'float' in param_type:
            return 1e10
        else:
            return 255
    
    def _generate_edge(self, param_type):
        """엣지 케이스 값 생성"""
        edge_values = [0, 1, -1, 255, 256, -128, 127, 65535, 65536, -32768, 32767]
        if 'uint' in param_type or 'int' in param_type:
            return random.choice(edge_values)
        elif 'double' in param_type or 'float' in param_type:
            return random.choice([0.0, 1.0, -1.0, 1e10, -1e10, float('inf'), float('-inf')])
        else:
            return random.choice(edge_values)


class CommandDBParser:
    """Cmd DB CSV 파서"""
    
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.commands = {}
        self._parse()
    
    def _parse(self):
        """CSV 파일 파싱"""
        if not os.path.exists(self.csv_path):
            print(f"Warning: Cmd DB CSV 파일을 찾을 수 없습니다: {self.csv_path}")
            return
        
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                rows = list(reader)
                
                for i in range(3, len(rows)):
                    row = rows[i]
                    
                    if len(row) < 5 or not row[1] or row[1].startswith('*'):
                        continue
                    
                    cmd_name = row[1].strip()
                    
                    # Code 파싱
                    code_str = row[3].strip()
                    if not code_str:
                        continue
                    
                    try:
                        if code_str.startswith('0x') or code_str.startswith('0X'):
                            cmd_code = int(code_str, 16)
                        else:
                            cmd_code = int(code_str)
                    except ValueError:
                        continue
                    
                    # 파라미터 정보
                    try:
                        num_params = int(row[4]) if row[4] else 0
                    except ValueError:
                        num_params = 0
                    
                    param_types = []
                    param_descriptions = []
                    
                    for j in range(num_params):
                        type_col = 5 + j * 2
                        desc_col = 6 + j * 2
                        
                        param_type = row[type_col].strip() if type_col < len(row) and row[type_col] else ""
                        param_desc = row[desc_col].strip() if desc_col < len(row) and row[desc_col] else ""
                        
                        param_types.append(param_type)
                        param_descriptions.append(param_desc)
                    
                    description = row[19].strip() if len(row) > 19 and row[19] else ""
                    danger_flag = len(row) > 18 and row[18] and row[18].strip().lower() == "danger"
                    
                    self.commands[cmd_name] = {
                        'code': cmd_code,
                        'num_params': num_params,
                        'param_types': param_types,
                        'param_descriptions': param_descriptions,
                        'description': description,
                        'danger_flag': danger_flag
                    }
        except Exception as e:
            print(f"Error parsing Cmd DB CSV: {e}")
    
    def get_command_info(self, cmd_name):
        """명령 정보 가져오기"""
        return self.commands.get(cmd_name)
    
    def get_all_commands(self):
        """모든 명령 정보 반환"""
        return self.commands


def generate_params_from_cmd_info(cmd_info, generator=None):
    """
    명령 정보로부터 파라미터 튜플 생성
    
    Args:
        cmd_info: 명령 정보 딕셔너리
        generator: FuzzingParamGenerator 인스턴스 (None이면 기본 생성)
    
    Returns:
        tuple: 파라미터 튜플
    """
    if generator is None:
        generator = FuzzingParamGenerator()
    
    if cmd_info['num_params'] == 0:
        return ()
    
    params = []
    for i in range(cmd_info['num_params']):
        param_type = cmd_info['param_types'][i] if i < len(cmd_info['param_types']) else "uint32_t"
        param_desc = cmd_info['param_descriptions'][i] if i < len(cmd_info['param_descriptions']) else ""
        
        value = generator.generate_value(param_type, param_desc)
        params.append(value)
    
    return tuple(params)


def get_all_cmd_codes_from_enum(c2a_enum):
    """
    c2a_enum에서 모든 Cmd_CODE_* 속성을 가져옴
    
    Args:
        c2a_enum: c2a_enum 객체
    
    Returns:
        dict: {cmd_name: cmd_code} 형태의 딕셔너리
    """
    cmd_codes = {}
    for attr_name in dir(c2a_enum):
        if attr_name.startswith('Cmd_CODE_'):
            cmd_name = attr_name.replace('Cmd_CODE_', '')
            try:
                cmd_code = getattr(c2a_enum, attr_name)
                cmd_codes[cmd_name] = cmd_code
            except:
                pass
    return cmd_codes


