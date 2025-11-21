# C2A 커맨드 퍼징 가이드

이 디렉토리에는 C2A의 모든 커맨드를 자동으로 테스트하는 퍼징 스크립트가 포함되어 있습니다.

## 파일 구조

- `test_fuzzing_all_commands.py`: 메인 퍼징 스크립트
- `fuzzing_helper.py`: 퍼징 유틸리티 함수들

## 사용 방법

### 1. 기본 사용법 (모든 명령을 Realtime Command로 테스트)

```bash
pytest test_fuzzing_all_commands.py::test_fuzz_all_commands_rt -v
```

### 2. 전략별 퍼징

퍼징 전략을 선택할 수 있습니다:
- `random`: 랜덤 값 생성 (기본값)
- `min`: 최소값 사용
- `max`: 최대값 사용
- `edge`: 엣지 케이스 값 사용

```python
# pytest에서 파라미터 전달
pytest test_fuzzing_all_commands.py::test_fuzz_all_commands_rt -v --strategy=random
```

### 3. 제한된 명령 수로 테스트

```python
# 처음 10개 명령만 테스트
test_fuzz_all_commands_rt(strategy="random", max_commands=10)
```

### 4. 명령 목록 확인

```python
python test_fuzzing_all_commands.py
```

이렇게 실행하면 모든 명령과 파라미터 정보가 출력됩니다.

## 커맨드 전송 방법

### Realtime Command (즉시 실행)

```python
from fuzzing_helper import CommandDBParser, FuzzingParamGenerator, generate_params_from_cmd_info
import wings_utils, c2a_enum_utils

c2a_enum = c2a_enum_utils.get_c2a_enum()
ope = wings_utils.get_wings_operation()

# 명령 정보 가져오기
cmd_db = CommandDBParser("path/to/cmd_db.csv")
cmd_info = cmd_db.get_command_info("NOP")

# 파라미터 생성
generator = FuzzingParamGenerator(strategy="random")
params = generate_params_from_cmd_info(cmd_info, generator)

# 명령 전송
result = wings.util.send_rt_cmd_and_confirm(
    ope, c2a_enum.Cmd_CODE_NOP, params, c2a_enum.Tlm_CODE_HK
)
```

### Timeline Command (지정된 TI에 실행)

```python
# 현재 TI 가져오기
tlm_HK = wings.util.generate_and_receive_tlm(
    ope, c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM, c2a_enum.Tlm_CODE_HK
)
current_ti = tlm_HK["HK.SH.TI"]
future_ti = current_ti + 10000  # 10000 cycle 후

# Timeline Command 전송
wings.util.send_tl_cmd(ope, future_ti, c2a_enum.Cmd_CODE_NOP, ())
```

### Block Command

```python
# Block Command 전송
ope.send_bl_cmd(future_ti, c2a_enum.Cmd_CODE_NOP, ())
```

## 파라미터 자동 생성

`FuzzingParamGenerator`는 파라미터 타입에 따라 자동으로 값을 생성합니다:

- `uint8_t`, `int8_t`: 0-255 또는 -128-127
- `uint16_t`, `int16_t`: 0-65535 또는 -32768-32767
- `uint32_t`, `int32_t`: 32비트 정수 범위
- `double`, `float`: 부동소수점 값
- `raw`: 16진수 문자열 (예: "0x12345678")

## Cmd DB CSV 구조

Cmd DB CSV 파일에서 다음 정보를 자동으로 파싱합니다:

- 명령 이름
- 명령 코드 (16진수)
- 파라미터 개수
- 각 파라미터의 타입과 설명
- 명령 설명
- Danger Flag

## 결과 해석

퍼징 결과는 다음과 같은 상태 코드를 반환합니다:

- `SUC`: 성공 (Success)
- `PRM`: 파라미터 오류 (Parameter Error)
- `CNT`: 제약 조건 위반 (Constraint Error)
- `ROE`: 실행 순서 오류 (Runtime Order Error)
- `ERR`: 기타 오류

## 주의사항

1. **Danger Flag가 있는 명령**: 위험한 명령은 주의해서 테스트하세요.
2. **파라미터 검증**: 일부 명령은 특정 범위의 파라미터만 받을 수 있습니다.
3. **실행 순서**: 일부 명령은 다른 명령 실행 후에만 동작할 수 있습니다.
4. **상태 의존성**: C2A의 현재 상태에 따라 명령 실행 결과가 달라질 수 있습니다.

## 커스터마이징

### 커스텀 파라미터 생성기

```python
class CustomParamGenerator(FuzzingParamGenerator):
    def _generate_random(self, param_type, param_desc):
        # 커스텀 로직 구현
        if "address" in param_desc.lower():
            return 0x1000  # 특정 주소 값
        return super()._generate_random(param_type, param_desc)
```

### 특정 명령만 테스트

```python
commands_to_test = ["NOP", "TMGR_SET_TIME", "AM_REGISTER_APP"]
for cmd_name in commands_to_test:
    cmd_code = getattr(c2a_enum, f"Cmd_CODE_{cmd_name}")
    # 테스트 로직
```

## 예제

전체 예제는 `test_fuzzing_all_commands.py` 파일을 참고하세요.


