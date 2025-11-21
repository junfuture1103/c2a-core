#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

import isslwings as wings
import pytest

# ROOT_PATH = "../../../"
ROOT_PATH = "../../"
path = os.path.dirname(__file__) + "/" + ROOT_PATH + "utils"
print(path)

sys.path.append(os.path.dirname(__file__) + "/" + ROOT_PATH + "utils")
import c2a_enum_utils
import wings_utils

c2a_enum = c2a_enum_utils.get_c2a_enum()
ope = wings_utils.get_wings_operation()

@pytest.mark.real
@pytest.mark.sils
def test_event_utility():
    tlm_EH = wings.util.generate_and_receive_tlm(
        ope, c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM, c2a_enum.Tlm_CODE_EH
    )
    print("c2a_enum.Cmd_CODE_TG_GENERATE_RT_TLM", dir(c2a_enum))
    print("tlm_EH : ", tlm_EH)
    print("tlm_EH[EH.EVENT_UTIL.IS_ENABLED_EH_EXECUTION] : ", tlm_EH["EH.EVENT_UTIL.IS_ENABLED_EH_EXECUTION"])
    assert tlm_EH["EH.EVENT_UTIL.IS_ENABLED_EH_EXECUTION"] == "ENABLE"

def test_send_nop():
    wings.util.send_rt_cmd_and_confirm(
        ope, c2a_enum.Cmd_CODE_NOP, (), c2a_enum.Tlm_CODE_HK
    )

def test_tmgr_set_time():
    wings.util.send_rt_cmd_and_confirm(
        ope, c2a_enum.Cmd_CODE_TMGR_SET_TIME, (0xFFFFFFFF,), c2a_enum.Tlm_CODE_HK
    )

if __name__ == "__main__":
    test_send_nop()
    # test_tmgr_set_time()

