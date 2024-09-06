from collections import defaultdict
import traceback
from itertools import chain
from typing import Dict, List, Mapping, Set, Tuple
import argparse
import os
import pandas as pd
import sys
import re
import copy
import requests
import json
from web3 import Web3
from pm_token import (
    AKToken,
    AKPair,
    CommonSwapFuncSig,
    ERCXXXToken,
    FlashAction,
    PoolAction,
    BalanceRelated,
    PoolOpAction,
    FlashCallback,
    PairSwapSigs,
    TokenAction,
)


sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from clientlib.facts_to_cfg import (
    load_csv_map,
    load_csv_multimap,
    load_csv,
    Statement,
    Block,
)

with open("./template.json", "r") as file:
    template_mappings = json.load(file)


class Call_Node:
    def __init__(
        self,
        ident: str = None,
        addr: str = None,
        selector: str = None,
        calltype: str = None,
    ):
        self.ident = ident
        self.addr = addr
        self.selector = selector
        self.predecessors: Set[Call_Node] = set()
        self.successors: Set[Call_Node] = set()
        self.selector_name = None
        self.calltype: str = calltype
        self.tokens: Dict[str, AKToken] = {}
        self.pairs: Dict[str, AKPair] = {}
        self.params = {}
        self.ret2Arg = []
        self.tokenInfo = []
        self.tokenActions = []


class Function:
    def __init__(
        self,
        ident: str = None,
        name: str = None,
        head_block: Block = None,
        is_public: bool = None,
        formals: List[str] = None,
    ):
        self.ident = ident
        self.name = name
        self.formals = formals
        self.is_public = is_public
        self.head_block = head_block


class CallInfo:
    def __init__(self, addr: str = None, selector: str = None):
        self.call_addr = addr
        self.selector = selector


"""
    include 2 parts
    1. call_node: from which callsite
    2. call_info: call_addr and selector that passed to the next callsite
    or you can regard it as Union like C
"""


class Call_Pass:
    def __init__(
        self,
        callsite: str = None,
        addr: str = None,
        selector: str = None,
        call_info_addr: str = None,
        call_info_selector: str = None,
    ):
        self.callsite = callsite
        self.call_addr = addr
        self.selector = selector
        self.call_info_addr = call_info_addr
        self.call_info_selector = call_info_selector
        self.calltype: str = None

    def __eq__(self, other):
        if not isinstance(other, Call_Pass):
            return NotImplemented
        return (
            self.callsite == self.callsite
            and self.call_addr == other.call_addr
            and self.selector == other.selector
            and self.call_info_addr == other.call_info_addr
            and self.call_info_selector == other.call_info_selector
        )

    def __hash__(self):
        return hash(
            (
                self.callsite,
                self.call_addr,
                self.selector,
                self.call_info_addr,
                self.call_info_selector,
            )
        )


class Fact(object):
    def __init__(self) -> None:
        self.Infact: Set[Call_Pass] = set()
        self.Outfact: Set[Call_Pass] = set()


class Contract:
    def __init__(
        self, chain=None, addr=None, canTrace=False, delegateOrigin=None, level=0
    ):
        self.chain = chain
        self.addr = addr
        self.canTrace = canTrace
        self.Level = level
        self.callContract: Dict[str, Contract] = {}
        # delegateCall origin contract, keep it for getting storage info
        self.delegateOrigin = delegateOrigin
        self.ToDelegate = None
        self.IsFlash = False

        self.func_info: Dict[str, ContractFunc] = {}
        self.DetectRes = set()
        self.parent = ""

        if self.chain == "bsc":
            self.rpc_url = "https://bsc-dataseed2.defibit.io/"
        elif self.chain == "eth":
            self.rpc_url = (
                "https://mainnet.infura.io/v3/fa3f945546d84dcaa747701c2ce7c6de"
            )

        self.getBytecodeOnline()

    def analyze_contract(self):
        try:
            if self.canTrace:
                if not os.path.exists(
                    "./codes/{contract_hex}.hex".format(contract_hex=self.addr)
                ):
                    return
                command = "./gigahorse.py --reuse_datalog_bin -C  ./pm_detect/pm.dl ./codes/{contract_hex}.hex "
                os.system(command.format(contract_hex=self.addr))
            else:
                if not os.path.exists(
                    "./codes/{contract_hex}.hex".format(
                        contract_hex=self.parent + "_" + self.addr
                    )
                ):
                    return
                command = "./gigahorse.py --reuse_datalog_bin -C ./pm_detect/pm.dl  ./codes/{contract_hex}.hex "
                os.system(command.format(contract_hex=self.parent + "_" + self.addr))

            if self.canTrace:
                self.get_funcs()
                self.init_info()
                self.get_func_nodeMap()
                self.swapInfo = self.detect_ArbitrageSwap()

                for _, val in self.func_info.items():
                    self.findAllPotentialSwapwithToken(val)

                for _, val in self.func_info.items():
                    self.recoverCallParamsWithRet(val)

                self.detect_SensitivePath()
                if args.dot:
                    self.getDot()
                self.WriteDetectingRes()
            else:
                self.get_funcs()
                self.init_info()

        except Exception as e:
            traceback.print_exc()

    def get_func_nodeMap(self):
        for function in sorted(self.contract_funcs.values(), key=lambda x: x.ident):
            if function.ident == "0x0":
                continue
            self.getSpecificNodeMap(function.ident)

    def getSpecificNodeMap(self, funcIdent):
        fc = self.contract_funcs[funcIdent]
        func = ContractFunc(fc, self)
        func.analyze()

        self.func_info[func.funcSig.ident] = func

        if func.NodeMap:
            for _, node in func.NodeMap.items():
                if node.ident == "ENTRY" or node.ident == "EXIT":
                    continue
                if node.selector:
                    temp_selector = get4bytesinfo(node.selector)
                    temp_selector = (
                        node.selector if temp_selector == "UNKNOWN" else temp_selector
                    )
                    if temp_selector != "UNKNOWN":
                        node.selector_name = temp_selector
                    else:
                        node.selector_name = node.selector

    def get_funcs(self):
        old_addr = self.addr
        if not self.canTrace:
            self.addr = self.parent + "_" + self.addr
        self.blocks, self.contract_funcs = get_funcs_info(
            "./.temp/" + self.addr + "/out/"
        )
        self.addr = old_addr

    def init_info(self):
        old_addr = self.addr
        if not self.canTrace:
            self.addr = self.parent + "_" + self.addr
        self.tac_variable_value = load_csv_map(
            "./.temp/" + self.addr + "/out/" + "TAC_Variable_Value.csv"
        )
        self.memory_4bytes = load_csv_map(
            "./.temp/" + self.addr + "/out/" + "AK_Func_4Bytes.csv"
        )
        publicFuncSig = load_csv_map(
            "./.temp/" + self.addr + "/out/" + "PublicFunction.csv"
        )
        add_0 = lambda x: "0x0" + x[2:] if len(x) == 9 else x
        transformed_list = [add_0(x) for x in publicFuncSig.values()]
        self.mapPublicFuncSig = {}
        for key, val in publicFuncSig.items():
            self.mapPublicFuncSig[add_0(val)] = key
        self.publicFuncSig = transformed_list
        loc = "./.temp/" + self.addr + "/out/" + "AK_Call_Addr_withType.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.call_addr_df = pd.read_csv(loc, header=None, sep="	")
            self.call_addr_df.columns = [
                "callsite",
                "var",
                "origin_var",
                "type",
                "addr",
            ]
        else:
            self.call_addr_df = pd.DataFrame(
                columns=["callsite", "var", "origin_var", "type", "addr"]
            )

        loc = "./.temp/" + self.addr + "/out/" + "AK_TraceCallArrayParams.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.call_arrayParams_df = pd.read_csv(loc, header=None, sep="	")
            self.call_arrayParams_df.columns = [
                "callsite",
                "idxVar",
                "idxNum",
                "finalVar",
                "slotNum",
                "addrType",
                "argIdx",
            ]
        else:
            self.call_arrayParams_df = pd.DataFrame(
                columns=[
                    "callsite",
                    "idxVar",
                    "idxNum",
                    "finalVar",
                    "slotNum",
                    "addrType",
                    "argIdx",
                ]
            )

        loc = "./.temp/" + self.addr + "/out/" + "AK_RetToCallArg.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.call_ret2callArg_df = pd.read_csv(loc, header=None, sep="	")
            self.call_ret2callArg_df.columns = [
                "callStmt1",
                "callRet",
                "callRetIndex",
                "callStmt2",
                "callArgIndex",
                "callArg",
            ]
        else:
            self.call_ret2callArg_df = pd.DataFrame(
                columns=[
                    "callStmt1",
                    "callRet",
                    "callRetIndex",
                    "callStmt2",
                    "callArgIndex",
                    "callArg",
                ]
            )

        loc = "./.temp/" + self.addr + "/out/" + "AK_TraceCallMemParams.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.call_memParams_df = pd.read_csv(loc, header=None, sep="	")
            self.call_memParams_df.columns = ["callsite", "argIdx", "addr", "arg"]
        else:
            self.call_memParams_df = pd.DataFrame(
                columns=["callsite", "argIdx", "addr", "arg"]
            )

        self.revert_blocks = load_single_column_csv(
            "./.temp/" + self.addr + "/out/" + "AK_Revert_Block.csv"
        )
        self.call_blocks = load_csv_multimap(
            "./.temp/" + self.addr + "/out/" + "AK_Func_Call_Block.csv"
        )
        self.call_stmts = load_csv_multimap(
            "./.temp/" + self.addr + "/out/" + "AK_Func_Call_Stmt.csv"
        )
        self.tac_block_stmts = load_csv_map(
            "./.temp/" + self.addr + "/out/" + "TAC_Block.csv"
        )
        self.tac_function_blocks = load_csv_multimap(
            "./.temp/" + self.addr + "/out/" + "InFunction.csv", reverse=True
        )

        loc = "./.temp/" + self.addr + "/out/" + "AK_CallTaintParams.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.callTaint_df = pd.read_csv(loc, header=None, sep="	")
            self.callTaint_df.columns = ["callsite", "addrVar", "addrType", "argIdx"]
        else:
            self.callTaint_df = pd.DataFrame(
                columns=["callsite", "addrVar", "addrType", "argIdx"]
            )

        loc = "./.temp/" + self.addr + "/out/" + "AK_CallStorageParams.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.callSlot_df = pd.read_csv(loc, header=None, sep="	")
            self.callSlot_df.columns = ["callsite", "addrVar", "slotNum", "argIdx"]
        else:
            self.callSlot_df = pd.DataFrame(
                columns=["callsite", "addrVar", "slotNum", "argIdx"]
            )

        loc = "./.temp/" + self.addr + "/out/" + "AK_CallConstParams.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.callConst_df = pd.read_csv(loc, header=None, sep="	")
            self.callConst_df.columns = ["callsite", "addrVar", "value", "argIdx"]
        else:
            self.callConst_df = pd.DataFrame(
                columns=["callsite", "addrVar", "value", "argIdx"]
            )

        loc = "./.temp/" + self.addr + "/out/" + "AK_CallCallDataParams.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.callCalldata_df = pd.read_csv(loc, header=None, sep="	")
            self.callCalldata_df.columns = ["callsite", "addrVar", "offset", "argIdx"]
        else:
            self.callCalldata_df = pd.DataFrame(
                columns=["callsite", "addrVar", "offset", "argIdx"]
            )
        self.callparamIsAddr = load_csv_multimap(
            "./.temp/" + self.addr + "/out/" + "AK_CallParamIsAddr.csv"
        )

        loc = "./.temp/" + self.addr + "/out/" + "AK_CallRestParams.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.callRest_df = pd.read_csv(loc, header=None, sep="	")
            self.callRest_df.columns = ["callsite", "paramVar", "argIdx"]
        else:
            self.callRest_df = pd.DataFrame(columns=["callsite", "paramVar", "argIdx"])

        self.callParamsNum = load_csv_map(
            "./.temp/" + self.addr + "/out/" + "AK_CallParamsNum.csv"
        )

        loc = "./.temp/" + self.addr + "/out/" + "AK_RetToCallArg.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            self.callRet2Arg_df = pd.read_csv(loc, header=None, sep="	")
            self.callRet2Arg_df.columns = [
                "callStmt1",
                "callRet",
                "callRetIndex",
                "callStmt2",
                "callArgIndex",
                "callArg",
            ]
        else:
            self.callRet2Arg_df = pd.DataFrame(
                columns=[
                    "callStmt1",
                    "callRet",
                    "callRetIndex",
                    "callStmt2",
                    "callArgIndex",
                    "callArg",
                ]
            )

        self.callWithSelfBalance = load_single_column_csv(
            "./.temp/" + self.addr + "/out/" + "AK_CallwithSelfBalanceValue.csv"
        )

        self.addr = old_addr

    def getBytecodeOnline(self, ifCross=""):
        if not os.path.exists("./codes"):
            os.makedirs("./codes")
        if ifCross == "":
            loc = f"./codes/{self.addr}.hex"
        else:
            cross_loc = ifCross + "_" + self.addr
            loc = f"./codes/{cross_loc}.hex"
        if os.path.exists(loc):
            return
        else:
            try:
                web3 = Web3(Web3.HTTPProvider(self.rpc_url))
                address = web3.to_checksum_address(self.addr)
                code = web3.eth.get_code(address).hex()
                if code != "" or code != "0x":
                    with open(loc, "w") as f:
                        f.write(code)
            except Exception as e:
                info = f"checksum or get runtime code error: {e} \n"
                print(info)

    def getStorageInfo(self, addr):
        if len(addr) == 42:
            return addr
        elif "slot" in addr or addr.startswith("0x"):
            web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if "slot" in addr:
                slot = addr.split("_")[1]
            else:
                slot = addr
            if self.delegateOrigin == None:
                contract_address = web3.to_checksum_address(self.addr)
            else:
                contract_address = web3.to_checksum_address(self.delegateOrigin)
            storage_data = web3.eth.get_storage_at(contract_address, int(slot, 16))
            target_addr = "0x" + storage_data.hex()[-40:]
            if target_addr != "0x0000000000000000000000000000000000000000":
                addr = target_addr
                return addr
        return None

    def getCheckSumAddress(self, addr):
        if not addr.startswith("0x"):
            return addr
        if len(addr) != 42:
            add0 = lambda x: "0x" + (42 - len(x)) * "0" + x[2:] if len(x) < 42 else x
            return add0(addr)
        else:
            return Web3.to_checksum_address(addr)

    def isPotentialSwap(self, node: Call_Node):
        return (
            any(node.selector == selector[1] for selector in self.swapInfo)
            and node.calltype == "CALL"
        )

    def findAllPotentialSwapwithToken(self, val):
        for key, node in val.NodeMap.items():
            if key == "ENTRY" or key == "EXIT":
                continue
            if node.selector and node.addr:
                addr = node.addr
                storage_addr = self.getStorageInfo(addr)
                if storage_addr == None:
                    storage_addr = addr
                storage_addr = self.getCheckSumAddress(storage_addr)
                node.addr = storage_addr

                if (
                    "flash" in node.selector_name.lower()
                    and "back" not in node.selector_name.lower()
                ) or node.selector in FlashAction:
                    self.IsFlash = True

                if any(node.selector == sig for sig in ERCXXXToken):
                    if storage_addr not in node.tokens.keys():
                        node.tokens[storage_addr] = AKToken(tokenAddr=storage_addr)
                try:
                    if (
                        node.selector in CommonSwapFuncSig
                        or node.selector in FlashAction
                    ):
                        val.hasSwap = True
                        if storage_addr not in node.pairs.keys():
                            node.pairs[storage_addr] = AKPair(
                                self.chain, pair_addr=storage_addr
                            )
                            if not storage_addr.startswith("0x"):
                                flag = False
                            else:
                                # special case for exchange/swap, we need to get token0 and token1 by on-chain supplyment
                                if node.selector == "0xa6417ed6":
                                    flag = node.pairs[storage_addr].GetIthToken(0, 1)
                                else:
                                    flag = node.pairs[storage_addr].GetToken0and1()
                            if flag:
                                node.tokens[
                                    node.pairs[storage_addr].token0.tokenAddr
                                ] = copy.copy(node.pairs[storage_addr].token0)
                                node.tokens[
                                    node.pairs[storage_addr].token1.tokenAddr
                                ] = copy.copy(node.pairs[storage_addr].token1)
                            else:
                                del node.pairs[storage_addr]

                    elif self.isPotentialSwap(node) or node.selector in PoolAction:
                        val.hasSwap = True

                        for _, row in self.call_memParams_df.iterrows():
                            if row["callsite"] == node.ident:
                                if (
                                    len(row["addr"]) == 42
                                    and row["addr"] not in node.tokens.keys()
                                ):
                                    row["addr"] = self.getCheckSumAddress(row["addr"])
                                    node.tokens[row["addr"]] = AKToken(
                                        tokenAddr=row["addr"]
                                    )

                        for _, row in self.call_arrayParams_df.iterrows():
                            if row["callsite"] == node.ident:
                                if (
                                    row["addrType"] == "CONST"
                                    and 39 <= len(row["slotNum"]) <= 42
                                    and row["slotNum"] not in node.tokens.keys()
                                ):
                                    add0 = (
                                        lambda x: "0x" + (42 - len(x)) * "0" + x[2:]
                                        if len(x) < 42
                                        else x
                                    )
                                    new_Addr = add0(row["slotNum"])
                                    node.tokens[new_Addr] = AKToken(tokenAddr=new_Addr)
                                elif row["addrType"] == "STORAGE":
                                    token_addr = self.getStorageInfo(row["slotNum"])
                                    if token_addr:
                                        token_addr = self.getCheckSumAddress(token_addr)
                                    if token_addr != None:
                                        if token_addr not in node.tokens.keys():
                                            node.tokens[token_addr] = AKToken(
                                                tokenAddr=token_addr
                                            )
                                    else:
                                        if (
                                            "slot_" + row["slotNum"]
                                            not in node.tokens.keys()
                                        ):
                                            node.tokens[
                                                "slot_" + row["slotNum"]
                                            ] = AKToken(
                                                tokenAddr="slot_" + row["slotNum"]
                                            )

                except Exception as e:
                    print("find swap and token error : ", e)

            for key, token in node.tokens.items():
                if key not in val.tokens.keys():
                    val.tokens[key] = copy.copy(token)
            for key, pair in node.pairs.items():
                if key not in val.pairs.keys():
                    val.pairs[key] = copy.copy(pair)

    def collect_callsite_dict(self):
        callsite_dict = {}
        for _, row in self.call_memParams_df.iterrows():
            if row["callsite"] not in callsite_dict:
                callsite_dict[row["callsite"]] = []
            if len(row["addr"]) == 42:
                callsite_dict[row["callsite"]].append(
                    (row["argIdx"], row["addr"], row["callsite"])
                )

        for _, row in self.call_arrayParams_df.iterrows():
            if row["callsite"] not in callsite_dict:
                callsite_dict[row["callsite"]] = []
            callsite_dict[row["callsite"]].append(
                (row["idxNum"], row["slotNum"], row["callsite"])
            )

        return callsite_dict

    def process_arbitrage_swaps(self, value, funcSig, selector, val):
        res = []
        n = len(val)
        for i in range(n):
            for j in range(i + 1, n):
                if len(val[i]) != 2 or len(val[j]) != 2:
                    continue
                # find swap params
                # 1. exists 2 different token address in reverse order (array or params)
                if (
                    val[i][0][1] == val[j][1][1]
                    and val[i][1][1] == val[j][0][1]
                    and val[i][0][0] == val[j][0][0]
                    and val[i][1][0] == val[j][1][0]
                ) or (
                    val[i][0][1] == val[j][0][1]
                    and val[i][1][1] == val[j][1][1]
                    and val[i][0][0] == val[j][1][0]
                    and val[i][1][0] == val[j][0][0]
                ):

                    # 2. Dataflow from balanceOf related func to the 'swap' func
                    target = [val[i][0][2], val[j][0][2]]
                    filtered_df = self.call_ret2callArg_df[
                        self.call_ret2callArg_df["callStmt2"].isin(target)
                    ]
                    callsite1 = filtered_df["callStmt1"].tolist()
                    for callsite in callsite1:
                        if callsite not in value.NodeMap.keys():
                            continue
                        if value.NodeMap[callsite].calltype != "STATICCALL":
                            continue
                        selector_name = value.NodeMap[callsite].selector_name
                        if any(
                            keyword.lower() in selector_name.lower()
                            for keyword in BalanceRelated
                        ):
                            res.append(
                                (
                                    value.funcSig.ident
                                    if hasattr(value, "funcSig")
                                    else None,
                                    selector,
                                    val[i][0][2],
                                    val[j][0][2],
                                )
                            )

        return res

    def detect_arbitrage_swap_generic(self, value):
        res = []
        callsite_dict = self.collect_callsite_dict()

        funcSig = {}
        for callsite in callsite_dict.keys():
            if callsite not in value.NodeMap.keys():
                continue
            selector = value.NodeMap[callsite].selector
            if selector not in funcSig:
                funcSig[selector] = []
            funcSig[selector].append(callsite_dict[callsite])

        for selector, val in funcSig.items():
            res.extend(self.process_arbitrage_swaps(value, funcSig, selector, val))

        return res

    def detectSpecificArbitrageSwap(self, value):
        return self.detect_arbitrage_swap_generic(value)

    def detect_ArbitrageSwap(self):
        res = []
        for _, value in self.func_info.items():
            res.extend(self.detect_arbitrage_swap_generic(value))
        return res

    def detect_PM_Attack(self, func):
        all_paths = []
        swap_nodes = []
        for callsite, val in func.NodeMap.items():
            if val.selector and val.selector_name:
                if self.isPotentialSwap(val):
                    swap_nodes.append(val)
                elif val.addr == "private_call":
                    if self.func_info[val.selector].hasSwap:
                        swap_nodes.append(val)

        for start_node in swap_nodes:
            stack = [(start_node, [start_node.ident])]
            visited = set()

            while stack:
                current_node, path = stack.pop()
                visited.add(current_node.ident)
                for successor in current_node.successors:
                    if successor in swap_nodes:
                        # Found a swap-to-swap path
                        path_identifiers = [ident for ident in path] + [successor.ident]
                        if path_identifiers not in all_paths:
                            all_paths.append(path_identifiers)

                    if successor.ident not in visited:
                        stack.append((successor, path + [successor.ident]))

        if len(all_paths) != 0:
            for swapPath in all_paths:
                swap_entry = func.NodeMap[swapPath[0]]
                actions = swap_entry.tokenActions
                pr0 = ""
                for action in actions:
                    if action.Type == "swap":
                        pr0 = action.caller
                currentActions = []
                for i in range(0, len(swapPath)):
                    node = func.NodeMap[swapPath[i]]
                    actions = node.tokenActions
                    if len(actions) == 0 and node.addr == "private_call":
                        actions = self.func_info[node.selector].FuncTokenActions
                    if len(actions) == 0 and node.addr and node.addr.startswith("0x"):
                        actions = self.CrossSpecificNodeMap(node)
                    if not actions:
                        continue
                    if len(actions) == 0:
                        continue

                    for action in actions:
                        if action.Type == "swap":
                            token0, token1 = action.swap_pairaddr
                            pr = action.caller
                            for pre_action in currentActions:
                                if (
                                    pre_action.Type == "transfer"
                                    or pre_action.Type == "transferfrom"
                                ):
                                    if (
                                        pre_action.caller == token0
                                        or pre_action.caller == token1
                                    ) and ((pr0 != "" and pr0 == pr) or pr0 == ""):
                                        if (
                                            pre_action.to_address == "CALLER"
                                            or pre_action.to_address == "ADDRESS"
                                            or pre_action.to_address
                                            == self.getCheckSumAddress(self.addr)
                                        ):
                                            info = f"@@@ Indirect price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                            print(info)
                                            self.DetectRes.add(info)
                                        elif pre_action.to_address == pr:
                                            info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                            print(info)
                                            self.DetectRes.add(info)

                                if pre_action.Type == "liquidty":
                                    ltoken0, ltoken1 = pre_action.swap_pairaddr
                                    if (
                                        (
                                            pre_action.to_address == "CALLER"
                                            or pre_action.to_address == "ADDRESS"
                                            or pre_action.to_address
                                            == self.getCheckSumAddress(self.addr)
                                        )
                                        and ((pr0 != "" and pr0 == pr) or pr0 == "")
                                        and (
                                            token0 in [ltoken0, ltoken1]
                                            or token1 in [ltoken0, ltoken1]
                                        )
                                    ):
                                        info = f"@@@ Indirect price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                        print(info)
                                        self.DetectRes.add(info)
                                    elif pre_action.to_address == pr:
                                        info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                        print(info)
                                        self.DetectRes.add(info)

                                if pre_action.Type != "swap":
                                    continue
                                pre_token0, pre_token1 = pre_action.swap_pairaddr

                                if pre_token1 == token0 and pre_token0 != token1:
                                    if self.IsFlash and node.ret2Arg:
                                        for callsite in node.ret2Arg:
                                            retNode = func.NodeMap[callsite]
                                            if any(
                                                keyword.lower()
                                                in node.selector_name.lower()
                                                for keyword in BalanceRelated
                                            ):
                                                info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite: {node.ident}, token: {pre_token0}, {token1}"
                                                print(info)
                                                self.DetectRes.add(info)
                                                continue

                                if pre_token0 != token1 or pre_token1 != token0:
                                    continue

                                if (
                                    token0
                                    == "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
                                    or token1
                                    == "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
                                ):
                                    if (
                                        node.ident in self.callWithSelfBalance
                                        and self.IsFlash
                                    ):
                                        info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite:  {node.ident}, token: {token0}, {token1}"
                                        print(info)
                                        self.DetectRes.add(info)
                                else:
                                    if node.ret2Arg and self.IsFlash:
                                        for callsite in node.ret2Arg:
                                            retNode = func.NodeMap[callsite]
                                            if any(
                                                keyword.lower()
                                                in retNode.selector_name.lower()
                                                for keyword in BalanceRelated
                                            ):
                                                info = f"@@@ Direct price manipulation in function: {func.funcSig.name}, callsite:  {node.ident}, token: {token0}, {token1}"
                                                print(info)
                                                self.DetectRes.add(info)
                        currentActions.append(action)

    def detect_SensitivePath(self):
        for _, val in self.func_info.items():
            if val.NodeMap:
                # fund-exchange
                self.detect_PM_Attack(val)
                # fund-prepare & fund-preparation, still not? try all paths
                if len(self.DetectRes) == 0:
                    self.detectAllPotentialPath(val)

    def detectAllPotentialPath(self, func):

        visited = set()
        stack = [(func.NodeMap["ENTRY"], [])]

        while stack:
            node, pre_actions = stack.pop()
            visited.add(node.ident)
            actions = node.tokenActions

            if node.ident != "ENTRY":
                if len(actions) == 0 and node.addr == "private_call":
                    node.tokenActions = actions = self.func_info[
                        node.selector
                    ].FuncTokenActions
                if len(actions) == 0 and node.addr and node.addr.startswith("0x"):
                    actions = self.CrossSpecificNodeMap(node)

            if actions and len(actions) != 0:
                new_actions = pre_actions + actions
                currentActions = copy.copy(pre_actions)

                for action in actions:
                    if action.Type == "swap":
                        token0, token1 = action.swap_pairaddr
                        # rule 3 & 4
                        for pre_action in currentActions:
                            if (
                                pre_action.Type == "transfer"
                                or pre_action.Type == "transferfrom"
                            ):
                                if (
                                    pre_action.caller == token0
                                    or pre_action.caller == token1
                                ):
                                    if (
                                        pre_action.to_address == "CALLER"
                                        or pre_action.to_address == "ADDRESS"
                                        or pre_action.to_address
                                        == self.getCheckSumAddress(self.addr)
                                    ):
                                        info = f"@@@ Indirect price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                        print(info)
                                        self.DetectRes.add(info)
                                    else:
                                        info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                        print(info)
                                        self.DetectRes.add(info)

                            if pre_action.Type == "liquidty":
                                ltoken0, ltoken1 = pre_action.swap_pairaddr
                                if (
                                    pre_action.to_address == "CALLER"
                                    or pre_action.to_address == "ADDRESS"
                                    or pre_action.to_address
                                    == self.getCheckSumAddress(self.addr)
                                ) and (
                                    token0 in [ltoken0, ltoken1]
                                    or token1 in [ltoken0, ltoken1]
                                ):
                                    info = f"@@@ Indirect price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                    print(info)
                                    self.DetectRes.add(info)
                                else:
                                    info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite:  {pre_action.ident}, key_func:{pre_action.selector_name}, token: {token0}, {token1}"
                                    print(info)
                                    self.DetectRes.add(info)

                            if pre_action.Type != "swap":
                                continue
                            pre_token0, pre_token1 = pre_action.swap_pairaddr

                            if pre_token1 == token0 and pre_token0 != token1:
                                if self.IsFlash and node.ret2Arg:
                                    for callsite in node.ret2Arg:
                                        retNode = func.NodeMap[callsite]
                                        if any(
                                            keyword.lower()
                                            in node.selector_name.lower()
                                            for keyword in BalanceRelated
                                        ):
                                            info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite: {node.ident}, token: {pre_token0}, {token1}"
                                            print(info)
                                            self.DetectRes.add(info)
                                            continue

                            if pre_token0 != token1 or pre_token1 != token0:
                                continue

                            # rule 2
                            # native tokens should be specically handled.
                            if (
                                token0 == "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
                                or token1
                                == "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
                            ):
                                if (
                                    node.ident in self.callWithSelfBalance
                                    and self.IsFlash
                                ):
                                    info = f"@@@ Direct price manipulation attack in function: {func.funcSig.name}, callsite:  {node.ident}, token: {token0}, {token1}"
                                    print(info)
                                    self.DetectRes.add(info)
                            else:
                                if node.ret2Arg and self.IsFlash:
                                    for callsite in node.ret2Arg:
                                        retNode = func.NodeMap[callsite]
                                        if any(
                                            keyword.lower()
                                            in retNode.selector_name.lower()
                                            for keyword in BalanceRelated
                                        ):
                                            info = f"@@@ Direct price manipulation in function: {func.funcSig.name}, callsite:  {node.ident}, token: {token0}, {token1}"
                                            print(info)
                                            self.DetectRes.add(info)

                    currentActions.append(action)

            else:
                new_actions = copy.copy(pre_actions)

            for successor in node.successors:
                if successor.ident not in visited:
                    stack.append((successor, new_actions))

    # recover call(include token operations)'s params
    # and trace the Dataflow of call_A Rets to call_B Args
    def recoverCallParamsWithRet(self, val):
        if len(val.tokens) == 0:
            if not val.hasSwap:
                return

        for callsite, node in val.NodeMap.items():
            if callsite == "ENTRY" or callsite == "EXIT":
                continue
            if callsite not in self.callParamsNum.keys():
                continue
            if self.callParamsNum[callsite] == "-1":
                continue
            if node.selector:
                try:
                    tempdf = self.callRet2Arg_df[
                        (self.callRet2Arg_df["callStmt2"] == callsite)
                    ]
                    if not tempdf.empty:
                        for _, row in tempdf.iterrows():
                            if callsite not in val.callret2arg.keys():
                                val.callret2arg[callsite] = []
                            val.callret2arg[callsite].append(row.to_dict())
                            node.ret2Arg.append(row["callStmt1"])
                except Exception as e:
                    print("ret to arg error", e)
                    traceback.print_exc()
                try:
                    Num = int(self.callParamsNum[callsite]) + 1
                    # a special case
                    if node.selector == "0x38ed1739":
                        Num = int(self.callParamsNum[callsite]) + 2
                    for i in range(1, Num):
                        tempdf = self.call_arrayParams_df[
                            (self.call_arrayParams_df["callsite"] == callsite)
                            & (self.call_arrayParams_df["argIdx"] == i)
                        ]
                        if not tempdf.empty:
                            max_value = (
                                tempdf["idxNum"].apply(lambda x: int(x, 16)).max() + 1
                            )
                            tempArray = [""] * max_value
                            for _, row in tempdf.iterrows():
                                if row["addrType"] == "STORAGE":
                                    addr = self.getStorageInfo(row["slotNum"])
                                    if addr:
                                        addr = self.getCheckSumAddress(addr)
                                        tempArray[int(row["idxNum"], 16)] = addr
                                    else:
                                        tempArray[int(row["idxNum"], 16)] = (
                                            "slot_" + row["slotNum"]
                                        )
                                elif row["addrType"] == "CALLDATA":
                                    tempArray[int(row["idxNum"], 16)] = (
                                        "calldata_" + row["slotNum"]
                                    )
                                else:
                                    tempArray[
                                        int(row["idxNum"], 16)
                                    ] = self.getCheckSumAddress(row["slotNum"])
                            node.params[i] = tempArray
                            continue

                        tempdf = self.call_memParams_df[
                            (self.call_memParams_df["callsite"] == callsite)
                            & (self.call_memParams_df["argIdx"] == i)
                        ]
                        if not tempdf.empty:
                            row = tempdf.iloc[0]
                            if len(row["addr"]) == 42:
                                node.params[i] = self.getCheckSumAddress(row["addr"])
                            elif row["addr"] == "address(this)":
                                node.params[i] = self.getCheckSumAddress(self.addr)
                            elif row["addr"].startswith("0x"):
                                node.params[i] = int(row["addr"], 16)
                            continue

                        tempdf = self.callTaint_df[
                            (self.callTaint_df["callsite"] == callsite)
                            & (self.callTaint_df["argIdx"] == i)
                        ]
                        if not tempdf.empty:
                            row = tempdf.iloc[0]
                            if row["addrType"] == "ADDRESS":
                                node.params[i] = self.getCheckSumAddress(self.addr)
                            else:
                                node.params[i] = row["addrType"]
                            continue

                        tempdf = self.callSlot_df[
                            (self.callSlot_df["callsite"] == callsite)
                            & (self.callSlot_df["argIdx"] == i)
                        ]
                        if not tempdf.empty:
                            row = tempdf.iloc[0]
                            addr = self.getStorageInfo(row["slotNum"])
                            if addr:
                                addr = self.getCheckSumAddress(addr)
                                node.params[i] = addr
                            else:
                                node.params[i] = "slot_" + row["slotNum"]
                            continue

                        tempdf = self.callCalldata_df[
                            (self.callCalldata_df["callsite"] == callsite)
                            & (self.callCalldata_df["argIdx"] == i)
                        ]
                        if not tempdf.empty:
                            row = tempdf.iloc[0]
                            node.params[i] = "calldata_" + row["offset"]
                            continue

                        tempdf = self.callConst_df[
                            (self.callConst_df["callsite"] == callsite)
                            & (self.callConst_df["argIdx"] == i)
                        ]
                        if not tempdf.empty:
                            row = tempdf.iloc[0]
                            if (
                                row["addrVar"] in self.callparamIsAddr[callsite]
                                or 39 <= len(row["value"]) <= 42
                            ):
                                add_0 = (
                                    lambda s: s
                                    if len(s) == 42
                                    else "0x" + "0" * (42 - len(s)) + s[2:]
                                )
                                node.params[i] = add_0(row["value"])
                            elif row["value"].startswith("0x"):
                                node.params[i] = int(row["value"], 16)
                            else:
                                node.params[i] = row["value"]
                            continue

                        tempdf = self.callRest_df[
                            (self.callRest_df["callsite"] == callsite)
                            & (self.callRest_df["argIdx"] == i)
                        ]
                        if not tempdf.empty:
                            row = tempdf.iloc[0]
                            node.params[i] = row["paramVar"]

                except Exception as e:
                    print("recovery Params error: ", e, callsite)
                    traceback.print_exc()

            self.handleABI(node, int(self.callParamsNum[callsite]))

            if len(node.tokenActions) > 0:
                val.FuncTokenActions.extend(node.tokenActions)

    def getDot(self):
        for _, val in self.func_info.items():
            if val.NodeMap:
                call_info_dot(val.NodeMap, val.Contract.addr, val.funcSig.name)

    def handleABI(self, node: Call_Node, paramNum: int):
        # if node.addr == None:
        #     return
        funcSig = node.selector
        if funcSig in ERCXXXToken:
            self.handleERC20ABI(node)
        elif funcSig in PairSwapSigs.keys():
            self.handleSwapFunc(node)
        elif funcSig in PoolOpAction:
            self.handlePoolOp(node)
        elif node.selector_name and "burn" in node.selector_name.lower():
            self.handleBurn(node, paramNum)
        elif node.selector_name and "mint" in node.selector_name.lower():
            self.handleMint(node, paramNum)

    def handlePoolOp(self, node: Call_Node):
        funcSig = node.selector
        try:
            lp_map = template_mappings["liquidity"]
            token0, token1, to_address = "NoTrace", "NoTrace", "NoTrace"
            if funcSig in lp_map:
                mapping = lp_map[funcSig]
                token0 = node.params.get(mapping["token0"], "NoTrace")
                # native token
                if mapping["token1"] == "native":
                    token1 = (
                        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
                        if self.chain == "eth"
                        else "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
                    )
                else:
                    token1 = node.params.get(mapping["token1"], "NoTrace")
                to_address = node.params.get(mapping["to_address"], "NoTrace")
                action = TokenAction(
                    ident=node.ident,
                    action_type="liquidty",
                    caller=node.addr,
                    to_address=to_address,
                    swap_pairaddr=(token0, token1),
                    selector_name=node.selector_name,
                )
                node.tokenActions.append(action)
            else:
                action = TokenAction(
                    ident=node.ident,
                    action_type="liquidty",
                    caller=node.addr,
                    to_address=to_address,
                    swap_pairaddr=(token0, token1),
                    selector_name=node.selector_name,
                )
                node.tokenActions.append(action)
        except Exception as e:
            print("handle pool function error: ", e)
            traceback.print_exc()

    def handleBurn(self, node: Call_Node, paramNum: int):
        action = TokenAction(
            ident=node.ident,
            action_type="liquidty",
            caller=node.addr,
            order_params=[],
            selector_name=node.selector_name,
            to_address="",
        )
        for i in range(1, paramNum + 1):
            addr = node.params[i]
            action.order_params.append(addr)

        node.tokenActions.append(action)

    def handleMint(self, node: Call_Node, paramNum: int):
        action = TokenAction(
            ident=node.ident,
            action_type="liquidty",
            caller=node.addr,
            order_params=[],
            selector_name=node.selector_name,
            to_address="",
        )
        for i in range(1, paramNum + 1):
            addr = node.params[i]
            action.order_params.append(addr)

        node.tokenActions.append(action)

    def handleERC20ABI(self, node: Call_Node):
        if not node.addr:
            return
        funcSig = node.selector
        if funcSig == "0xa9059cbb":
            token = node.tokens[node.addr]
            to_address = node.params.get(1, "NoTrace")
            amount = node.params.get(2, "NoTrace")
            node.tokenInfo.append(
                f"transfer token: {token.tokenAddr} (amount: {amount}) to address: {to_address}"
            )
            action = TokenAction(
                ident=node.ident,
                action_type="transfer",
                caller=token.tokenAddr,
                to_address=to_address,
                amountOut=amount,
                selector_name=node.selector_name,
            )
            node.tokenActions.append(action)
        elif funcSig == "0x23b872dd":
            token = node.tokens[node.addr]
            from_address = node.params.get(1, "NoTrace")
            to_address = node.params.get(2, "NoTrace")
            amount = node.params.get(3, "NoTrace")
            node.tokenInfo.append(
                f"transferFrom token: {token.tokenAddr} (amount: {amount}) from address: {from_address} to address: {to_address}"
            )
            action = TokenAction(
                ident=node.ident,
                action_type="transferfrom",
                caller=token.tokenAddr,
                from_address=from_address,
                to_address=to_address,
                amountOut=amount,
                selector_name=node.selector_name,
            )
            node.tokenActions.append(action)

    # handle swap function
    def handleSwapFunc(self, node: Call_Node):
        funcSig = node.selector
        try:
            swap_map = template_mappings["swap"]
            if funcSig in swap_map:
                mapping = swap_map[funcSig]
                if "amountIn" in mapping:
                    amountIn = node.params.get(mapping["amountIn"], "NoTrace")
                else:
                    amountIn = "NoTrace"
                if "amountOut" in mapping:
                    amountOut = node.params.get(mapping["amountOut"], "NoTrace")
                else:
                    amountOut = "NoTrace"
                token0, token1 = "NoTrace", "NoTrace"
                if "array" in mapping:
                    token_path = node.params.get(mapping["array"])
                    if isinstance(token_path, list) and len(token_path) >= 2:
                        token0 = token_path[0]
                        length = len(token_path)
                        token1 = token_path[length - 1]
                    else:
                        token0, token1 = "NoTrace", "NoTrace"
                elif "direct" in mapping:
                    if node.params.get(mapping["direct"]):
                        direct = node.params[mapping["direct"]]
                        if node.addr not in node.pairs.keys():
                            return
                        pair = node.pairs[node.addr]
                        if direct == "1":
                            token0, token1 = (
                                pair.token0.tokenAddr,
                                pair.token1.tokenAddr,
                            )
                        else:
                            token0, token1 = (
                                pair.token1.tokenAddr,
                                pair.token0.tokenAddr,
                            )
                elif "pair" in mapping:
                    if node.addr and node.addr in node.pairs.keys():
                        pair = node.pairs[node.addr]
                        token0, token1 = pair.token0.tokenAddr, pair.token1.tokenAddr
                if token0 == "NoTrace" and "token0" in mapping:
                    token0 = node.params.get(mapping["token0"], "NoTrace")
                if token1 == "NoTrace" and "token1" in mapping:
                    token1 = node.params.get(mapping["token1"], "NoTrace")

                if "to_address" in mapping:
                    to_address = node.params.get(mapping["to_address"], "NoTrace")
                elif "to_self" in mapping:
                    to_address = self.addr
                else:
                    to_address = "NoTrace"

                action = TokenAction(
                    ident=node.ident,
                    action_type="swap",
                    caller=node.addr,
                    to_address=to_address,
                    swap_pairaddr=(token0, token1),
                    amountIn=amountIn,
                    amountOut=amountOut,
                    selector_name=node.selector_name,
                )
                node.tokenActions.append(action)
                node.tokenInfo.append(
                    f"swap token0 : {token0} (amount: {amountIn}) to  token1: {token1}"
                )

        except Exception as e:
            print("handle swap function error: ", e)
            traceback.print_exc()

    def CrossSpecificNodeMap(self, callnode: Call_Node):
        if callnode.calltype == "STATICCALL":
            return []
        if callnode.selector and callnode.addr:
            addr = callnode.addr
            storage_addr = self.getStorageInfo(addr)
            if storage_addr == None:
                return []
            callnode.addr = storage_addr

            if callnode.calltype != "CALL":
                return []
            if storage_addr not in self.callContract.keys():
                self.callContract[storage_addr] = Contract(
                    self.chain, storage_addr, False, level=self.Level + 1
                )
                self.callContract[storage_addr].getBytecodeOnline(ifCross=self.addr)
                self.callContract[storage_addr].parent = self.addr
                self.callContract[storage_addr].analyze_contract()

                if callnode.selector in self.callContract[storage_addr].publicFuncSig:
                    funcIdent = self.callContract[storage_addr].mapPublicFuncSig[
                        callnode.selector
                    ]
                    self.callContract[storage_addr].getSpecificNodeMap(funcIdent)
                    func = self.callContract[storage_addr].func_info[funcIdent]
                    self.callContract[storage_addr].swapInfo = self.callContract[
                        storage_addr
                    ].detectSpecificArbitrageSwap(func)
                    self.callContract[storage_addr].findAllPotentialSwapwithToken(func)
                    self.callContract[storage_addr].recoverCallParamsWithRet(func)

                    for _, node in func.NodeMap.items():
                        if node.addr == "private_call":
                            self.callContract[storage_addr].getSpecificNodeMap(
                                node.selector
                            )
                            private_func = self.callContract[storage_addr].func_info[
                                node.selector
                            ]
                            self.callContract[
                                storage_addr
                            ].swapInfo = self.callContract[
                                storage_addr
                            ].detectSpecificArbitrageSwap(
                                private_func
                            )
                            self.callContract[
                                storage_addr
                            ].findAllPotentialSwapwithToken(private_func)
                            self.callContract[storage_addr].recoverCallParamsWithRet(
                                private_func
                            )
                            func.FuncTokenActions.extend(private_func.FuncTokenActions)
                        elif node.addr == "address(this)":
                            self.callContract[storage_addr].getSpecificNodeMap(
                                self.callContract[storage_addr].mapPublicFuncSig[
                                    node.selector
                                ]
                            )
                            call_func = self.callContract[storage_addr].func_info[
                                self.callContract[storage_addr].mapPublicFuncSig[
                                    node.selector
                                ]
                            ]
                            self.callContract[
                                storage_addr
                            ].swapInfo = self.callContract[
                                storage_addr
                            ].detectSpecificArbitrageSwap(
                                call_func
                            )
                            self.callContract[
                                storage_addr
                            ].findAllPotentialSwapwithToken(call_func)
                            self.callContract[storage_addr].recoverCallParamsWithRet(
                                call_func
                            )
                            func.FuncTokenActions.extend(call_func.FuncTokenActions)
                    callnode.tokenActions = copy.copy(func.FuncTokenActions)
                    return func.FuncTokenActions
                else:
                    # eip-1967 specific slot number
                    target_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
                    target_addr = self.callContract[storage_addr].getStorageInfo(
                        target_slot
                    )
                    if target_addr == None:
                        return []

                    if target_addr not in self.callContract.keys():
                        self.callContract[target_addr] = Contract(
                            self.chain,
                            target_addr,
                            False,
                            delegateOrigin=storage_addr,
                            level=self.Level + 1,
                        )
                        self.callContract[storage_addr].ToDelegate = target_addr
                        self.callContract[target_addr].getBytecodeOnline(
                            ifCross=self.addr
                        )
                        self.callContract[target_addr].parent = self.addr
                        self.callContract[target_addr].analyze_contract()

                        if (
                            callnode.selector
                            in self.callContract[target_addr].publicFuncSig
                        ):
                            funcIdent = self.callContract[target_addr].mapPublicFuncSig[
                                callnode.selector
                            ]
                            self.callContract[target_addr].getSpecificNodeMap(funcIdent)
                            func = self.callContract[target_addr].func_info[funcIdent]
                            self.callContract[target_addr].swapInfo = self.callContract[
                                target_addr
                            ].detectSpecificArbitrageSwap(func)
                            self.callContract[
                                target_addr
                            ].findAllPotentialSwapwithToken(func)
                            self.callContract[target_addr].recoverCallParamsWithRet(
                                func
                            )

                            for _, node in func.NodeMap.items():
                                if node.addr == "private_call":
                                    self.callContract[target_addr].getSpecificNodeMap(
                                        node.selector
                                    )
                                    private_func = self.callContract[
                                        target_addr
                                    ].func_info[node.selector]
                                    self.callContract[
                                        target_addr
                                    ].swapInfo = self.callContract[
                                        target_addr
                                    ].detectSpecificArbitrageSwap(
                                        private_func
                                    )
                                    self.callContract[
                                        target_addr
                                    ].findAllPotentialSwapwithToken(private_func)
                                    self.callContract[
                                        target_addr
                                    ].recoverCallParamsWithRet(private_func)
                                    func.FuncTokenActions.extend(
                                        private_func.FuncTokenActions
                                    )
                                elif node.addr == "address(this)":
                                    self.callContract[target_addr].getSpecificNodeMap(
                                        self.callContract[target_addr].mapPublicFuncSig[
                                            node.selector
                                        ]
                                    )
                                    call_func = self.callContract[
                                        target_addr
                                    ].func_info[
                                        self.callContract[target_addr].mapPublicFuncSig[
                                            node.selector
                                        ]
                                    ]
                                    self.callContract[
                                        target_addr
                                    ].swapInfo = self.callContract[
                                        target_addr
                                    ].detectSpecificArbitrageSwap(
                                        call_func
                                    )
                                    self.callContract[
                                        target_addr
                                    ].findAllPotentialSwapwithToken(call_func)
                                    self.callContract[
                                        target_addr
                                    ].recoverCallParamsWithRet(call_func)
                                    func.FuncTokenActions.extend(
                                        call_func.FuncTokenActions
                                    )
                            callnode.tokenActions = copy.copy(func.FuncTokenActions)
                            return func.FuncTokenActions
            else:
                if callnode.selector in self.callContract[storage_addr].publicFuncSig:
                    funcIdent = self.callContract[storage_addr].mapPublicFuncSig[
                        callnode.selector
                    ]
                    self.callContract[storage_addr].getSpecificNodeMap(funcIdent)
                    func = self.callContract[storage_addr].func_info[funcIdent]
                    callnode.tokenActions = copy.copy(func.FuncTokenActions)
                    return func.FuncTokenActions
                elif self.callContract[storage_addr].ToDelegate:
                    target_addr = self.callContract[storage_addr].ToDelegate
                    if (
                        callnode.selector
                        in self.callContract[target_addr].publicFuncSig
                    ):
                        funcIdent = self.callContract[target_addr].mapPublicFuncSig[
                            callnode.selector
                        ]
                        self.callContract[target_addr].getSpecificNodeMap(funcIdent)
                        func = self.callContract[target_addr].func_info[funcIdent]
                        callnode.tokenActions = copy.copy(func.FuncTokenActions)
                        return func.FuncTokenActions
            return []

    def WriteDetectingRes(self):
        if not os.path.exists("./detect_res"):
            os.makedirs("./detect_res")
        if len(self.DetectRes) == 0:
            return
        with open(f"./detect_res/{self.addr}.log", "w") as f:
            for item in self.DetectRes:
                print(item, file=f)


class ContractFunc:
    def __init__(self, funcSig: Function = None, contract: Contract = None):
        self.funcSig = funcSig
        self.Contract = contract
        self.all_block_nodes = self.Contract.tac_function_blocks[self.funcSig.ident]
        self.cycle_path = []
        self.pairs = {}
        self.tokens = {}
        self.callret2arg: Dict[str, List] = {}
        self.FuncTokenActions = []
        self.hasSwap = False

    def init_block_info(self):
        self.store_block_info: Dict[str, Call_Pass] = {}
        self.ext_block = None
        self.has_selfDestruct = False
        self.call_edges = {}
        self.callprivate_blocks = []

        # iterate all the blocks once to get call info and then store (through datalog)
        stop_flag = False
        for node_ident in self.all_block_nodes:
            if (
                len(self.Contract.blocks[node_ident].successors) == 0
                and node_ident not in self.Contract.revert_blocks
                and not stop_flag
            ):
                for stmt in self.Contract.blocks[node_ident].statements:
                    if stmt.op == "STOP":
                        stop_flag = True
                self.ext_block = node_ident
                # print("ext: ", self.funcSig.name, node_ident)
            self.store_block_info[node_ident] = Call_Pass()
            for stmt in self.Contract.blocks[node_ident].statements:
                if stmt.op == "CONST":
                    val = self.Contract.tac_variable_value.get(stmt.defs[0])
                    if val:
                        # add "0" => 4 bytes
                        if len(val) == 9 or len(val) == 65 or len(val) == 41:
                            val = "0x0" + val[2:]
                        # regex match
                        if len(val) == 10 or len(val) == 66:
                            pattern = r"0x[a-fA-F0-9]{8}"
                            match = re.search(pattern, val)
                            if match:
                                temp_4bytes = match.group()
                                if temp_4bytes not in ["0x10000000", "0xffffffff"]:
                                    self.store_block_info[
                                        node_ident
                                    ].call_info_selector = temp_4bytes
                        elif len(val) == 42:
                            pattern = r"0x[a-fA-F0-9]{40}"
                            match = re.search(pattern, val)
                            if match:
                                temp_addr = match.group()
                                if temp_addr not in [
                                    "0x1000000000000000000000000000000000000000",
                                    "0xffffffffffffffffffffffffffffffffffffffff",
                                ]:
                                    self.store_block_info[
                                        node_ident
                                    ].call_info_addr = temp_addr

                elif (
                    stmt.op == "CALL"
                    or stmt.op == "STATICCALL"
                    or stmt.op == "DELEGATECALL"
                ):
                    self.store_block_info[node_ident].callsite = stmt.ident
                    self.store_block_info[node_ident].calltype = stmt.op
                    # firstly lookup memory_model (accurate)
                    selector = self.Contract.memory_4bytes.get(stmt.ident)
                    if selector:
                        if len(selector) == 9:
                            selector = "0x0" + selector[2:]
                        elif len(selector) == 65:
                            selector = "0x0" + selector[2:9]
                        elif len(selector) == 66:
                            selector = "0x" + selector[2:10]
                        self.store_block_info[node_ident].selector = selector
                    # else:
                    #     # otherwise by normal tracing methods (not 100% right)
                    #     selector = call_info.selector

                    if (
                        not selector
                        and self.store_block_info[node_ident].call_info_selector
                    ):
                        self.store_block_info[
                            node_ident
                        ].selector = self.store_block_info[
                            node_ident
                        ].call_info_selector
                    try:
                        temp_df = self.Contract.call_addr_df[
                            self.Contract.call_addr_df["callsite"] == stmt.ident
                        ]
                    except Exception as e:
                        temp_df = {}
                    res_addr = None
                    if len(temp_df) != 0:
                        temp_type = temp_df["type"].values[0]
                        if temp_type == "CONST":
                            res_addr = temp_df["addr"].values[0]
                        elif temp_type == "ADDRESS":
                            res_addr = "address(this)"
                        elif temp_type == "CALLDATA":
                            res_addr = "contract(call_data)"
                        elif temp_type == "STORAGE":
                            res_addr = f"slot_{temp_df['addr'].values[0]}"
                        self.store_block_info[node_ident].call_addr = res_addr

                    if (
                        not res_addr
                        and self.store_block_info[node_ident].call_info_addr
                    ):
                        self.store_block_info[
                            node_ident
                        ].call_addr = self.store_block_info[node_ident].call_info_addr

                elif stmt.op == "CALLPRIVATE":
                    # if self.Contract.canTrace == False:
                    self.store_block_info[node_ident].callsite = stmt.ident
                    self.store_block_info[node_ident].calltype = "PRIVATE_CALL"
                    private_selector = self.Contract.tac_variable_value.get(
                        stmt.operands[0]
                    )
                    if private_selector:
                        self.call_edges[stmt.ident] = private_selector
                    self.store_block_info[node_ident].selector = private_selector
                    self.store_block_info[node_ident].call_addr = "private_call"
                    self.callprivate_blocks.append(node_ident)

                elif stmt.op == "SELFDESTRUCT":
                    self.has_selfDestruct = True

    def init_facts(self):
        self.block_callinfo_facts: Dict[str, Fact] = {}
        for node in self.all_block_nodes:
            self.block_callinfo_facts[node] = Fact()

        self.block_callinfo_facts[self.funcSig.head_block.ident].Infact.add(
            Call_Pass(
                callsite="ENTRY", addr=self.Contract.addr, selector=self.funcSig.ident
            )
        )

    def find_first_callnodes(self):
        stack = [(self.funcSig.head_block, "")]
        visited = set()
        self.head_callnodes = set()
        while stack:
            cur_node, has_call = stack.pop()
            visited.add(cur_node.ident)
            if cur_node.ident in self.Contract.call_blocks[self.funcSig.ident]:
                temp_stmt = ""
                for stmt in cur_node.statements:
                    if (
                        stmt.op == "CALL"
                        or stmt.op == "STATICCALL"
                        or stmt.op == "DELEGATECALL"
                        or stmt.op == "CALLPRIVATE"
                    ):
                        temp_stmt = stmt.ident
                        break
                if has_call == "":
                    self.head_callnodes.add(temp_stmt)
                has_call = temp_stmt

            for subblock in cur_node.successors:
                if subblock.ident not in visited:
                    stack.append((subblock, has_call))

        return self.head_callnodes

    def find_potential_callback(self):
        res = {}
        for callsite, block in self.Contract.potential_callback_blocks.items():
            if block in self.all_block_nodes:
                for stmt in self.Contract.blocks[block].statements:
                    if stmt.op == "CONST":
                        val = self.Contract.tac_variable_value.get(stmt.defs[0])
                        if val:
                            # add "0" => 4 bytes
                            if len(val) == 9 or len(val) == 65:
                                val = "0x0" + val[2:]
                            # regex match
                            if len(val) == 10 or len(val) == 66:
                                pattern = r"0x[a-fA-F0-9]{8}"
                                match = re.search(pattern, val)
                                if match:
                                    temp_4bytes = match.group()
                                    if (
                                        temp_4bytes not in ["0x10000000", "0xffffffff"]
                                        and temp_4bytes in self.Contract.publicFuncSig
                                    ):
                                        res[callsite] = temp_4bytes

        return res

    def analyze(self):
        self.NodeMap: Dict[str, Call_Node] = {}
        # in case only one revert block
        if self.funcSig.head_block.ident in self.Contract.revert_blocks:
            return None
        # forward analysis
        self.init_facts()
        self.init_block_info()
        # get the head call nodes
        self.find_first_callnodes()
        # self.find_potential_callback()
        if self.funcSig.ident not in self.Contract.call_blocks.keys():
            return None

        if self.Contract.canTrace:

            worklist = []

            # entry node's successors
            for ident in self.all_block_nodes:
                if ident not in self.Contract.revert_blocks:
                    worklist.append(self.Contract.blocks[ident])

            while worklist:
                cur_node = worklist.pop()
                old_outfact = copy.copy(
                    self.block_callinfo_facts[cur_node.ident].Outfact
                )

                for in_node in cur_node.predecessors:
                    self.block_callinfo_facts[
                        cur_node.ident
                    ].Infact |= self.block_callinfo_facts[in_node.ident].Outfact
                self.block_callinfo_facts[
                    cur_node.ident
                ].Outfact |= self.block_callinfo_facts[cur_node.ident].Infact

                # if it is a call code
                if cur_node.ident in self.Contract.call_blocks[self.funcSig.ident]:
                    if self.store_block_info[cur_node.ident].selector == None:
                        for call_pass in self.block_callinfo_facts[
                            cur_node.ident
                        ].Infact:
                            if (
                                call_pass.callsite == None
                                and call_pass.call_info_selector != None
                            ):
                                self.store_block_info[
                                    cur_node.ident
                                ].selector = call_pass.call_info_selector
                                break
                    # output is itself
                    self.block_callinfo_facts[cur_node.ident].Outfact.clear()

                    self.block_callinfo_facts[cur_node.ident].Outfact.add(
                        copy.copy(self.store_block_info[cur_node.ident])
                    )
                # if it is callprivate
                elif cur_node.ident in self.callprivate_blocks:
                    self.block_callinfo_facts[cur_node.ident].Outfact.clear()
                    self.block_callinfo_facts[cur_node.ident].Outfact.add(
                        copy.copy(self.store_block_info[cur_node.ident])
                    )
                # else pass call_info
                elif (
                    self.store_block_info[cur_node.ident].call_info_addr != None
                    or self.store_block_info[cur_node.ident].call_info_selector != None
                ):
                    self.block_callinfo_facts[cur_node.ident].Outfact.add(
                        Call_Pass(
                            call_info_addr=self.store_block_info[
                                cur_node.ident
                            ].call_info_addr,
                            call_info_selector=self.store_block_info[
                                cur_node.ident
                            ].call_info_selector,
                        )
                    )

                if old_outfact != self.block_callinfo_facts[cur_node.ident].Outfact:
                    for succ in cur_node.successors:
                        worklist.append(succ)

            # 1. initialize
            for call_stmt in self.Contract.call_stmts[self.funcSig.ident]:
                self.NodeMap[call_stmt] = Call_Node(
                    ident=call_stmt,
                    addr=self.store_block_info[
                        self.Contract.tac_block_stmts[call_stmt]
                    ].call_addr,
                    selector=self.store_block_info[
                        self.Contract.tac_block_stmts[call_stmt]
                    ].selector,
                    calltype=self.store_block_info[
                        self.Contract.tac_block_stmts[call_stmt]
                    ].calltype,
                )

            for call_stmt, func_sig in self.call_edges.items():
                self.NodeMap[call_stmt] = Call_Node(
                    ident=call_stmt, addr="private_call", selector=func_sig
                )

            # 2. build edge
            # add entry node
            # entry node'selector here means the function signature to distinguish different functions
            self.NodeMap["ENTRY"] = Call_Node(
                ident="ENTRY", addr=self.Contract.addr, selector=self.funcSig.ident
            )
            # add exit node
            self.NodeMap["EXIT"] = Call_Node(ident="EXIT")
            # for head_node in self.head_callnodes:
            #     self.NodeMap["ENTRY"].successors.add(self.NodeMap[head_node])
            # self.NodeMap[head_node].predecessors.add(self.NodeMap["ENTRY"])

            if len(self.NodeMap) <= 2:
                # means only entry -> exit
                self.NodeMap["ENTRY"].successors.add(self.NodeMap["EXIT"])

            for call_stmt in self.Contract.call_stmts[self.funcSig.ident]:
                for call_pass in self.block_callinfo_facts[
                    self.Contract.tac_block_stmts[call_stmt]
                ].Infact:
                    if (
                        call_pass.callsite != None
                        and call_pass.callsite in self.NodeMap.keys()
                    ):
                        self.NodeMap[call_pass.callsite].successors.add(
                            self.NodeMap[call_stmt]
                        )
                        self.NodeMap[call_stmt].predecessors.add(
                            self.NodeMap[call_pass.callsite]
                        )

            for call_edge in self.call_edges.keys():
                for call_pass in self.block_callinfo_facts[
                    self.Contract.tac_block_stmts[call_edge]
                ].Infact:
                    if call_pass.callsite != None:
                        self.NodeMap[call_pass.callsite].successors.add(
                            self.NodeMap[call_edge]
                        )
                        self.NodeMap[call_edge].predecessors.add(
                            self.NodeMap[call_pass.callsite]
                        )

            # 3. converge to exit node
            if self.ext_block != None:
                for call_pass in self.block_callinfo_facts[self.ext_block].Infact:
                    if call_pass.callsite != None:
                        self.NodeMap[call_pass.callsite].successors.add(
                            self.NodeMap["EXIT"]
                        )
                        self.NodeMap["EXIT"].predecessors.add(
                            self.NodeMap[call_pass.callsite]
                        )

            for call_stmt in self.Contract.call_stmts[self.funcSig.ident]:
                if len(self.NodeMap[call_stmt].successors) == 0:
                    self.NodeMap[call_stmt].successors.add(self.NodeMap["EXIT"])
                    self.NodeMap["EXIT"].predecessors.add(self.NodeMap[call_stmt])

            for call_edge in self.call_edges.keys():
                if len(self.NodeMap[call_edge].successors) == 0:
                    self.NodeMap[call_edge].successors.add(self.NodeMap["EXIT"])
                    self.NodeMap["EXIT"].predecessors.add(self.NodeMap[call_edge])

        else:
            for call_stmt in self.Contract.call_stmts[self.funcSig.ident]:
                self.NodeMap[call_stmt] = Call_Node(
                    ident=call_stmt,
                    addr=self.store_block_info[
                        self.Contract.tac_block_stmts[call_stmt]
                    ].call_addr,
                    selector=self.store_block_info[
                        self.Contract.tac_block_stmts[call_stmt]
                    ].selector,
                    calltype=self.store_block_info[
                        self.Contract.tac_block_stmts[call_stmt]
                    ].calltype,
                )
            for call_stmt, func_sig in self.call_edges.items():
                self.NodeMap[call_stmt] = Call_Node(
                    ident=call_stmt, addr="private_call", selector=func_sig
                )

        return self.NodeMap


def load_single_column_csv(path: str, seperator: str = "\t") -> List[str]:
    with open(path) as f:
        return [line.strip() for line in f.read().splitlines()]


def get_funcs_info(
    local_path: str,
) -> Tuple[Mapping[str, Block], Mapping[str, Function]]:
    tac_function_blocks = load_csv_multimap(local_path + "InFunction.csv", reverse=True)
    tac_func_id_to_public = load_csv_map(local_path + "PublicFunction.csv")
    tac_high_level_func_name = load_csv_map(local_path + "HighLevelFunctionName.csv")
    tac_formal_args: Mapping[str, List[Tuple[str, int]]] = defaultdict(list)
    for func_id, arg, pos in load_csv(local_path + "FormalArgs.csv"):
        tac_formal_args[func_id].append((arg, int(pos)))

    tac_block_function: Mapping[str, str] = {}
    for func_id, block_ids in tac_function_blocks.items():
        for block in block_ids:
            tac_block_function[block] = func_id

    tac_block_stmts = load_csv_multimap(local_path + "TAC_Block.csv", reverse=True)
    tac_op = load_csv_map(local_path + "TAC_Op.csv")

    tac_defs: Mapping[str, List[Tuple[str, int]]] = defaultdict(list)
    for stmt_id, var, pos in load_csv(local_path + "TAC_Def.csv"):
        tac_defs[stmt_id].append((var, int(pos)))

    tac_uses: Mapping[str, List[Tuple[str, int]]] = defaultdict(list)
    for stmt_id, var, pos in load_csv(local_path + "TAC_Use.csv"):
        tac_uses[stmt_id].append((var, int(pos)))

    tac_block_succ = load_csv_multimap(local_path + "LocalBlockEdge.csv")
    tac_block_pred: Mapping[str, List[str]] = defaultdict(list)
    for block, succs in tac_block_succ.items():
        for succ in succs:
            tac_block_pred[succ].append(block)

    def stmt_sort_key(stmt_id: str) -> int:
        return int(stmt_id.replace("S", "").split("0x")[1].split("_")[0], base=16)

    blocks: Mapping[str, Block] = {}
    for block_id in chain(*tac_function_blocks.values()):
        try:
            statements = [
                Statement(
                    s_id,
                    tac_op[s_id],
                    [var for var, _ in sorted(tac_uses[s_id], key=lambda x: x[1])],
                    [var for var, _ in sorted(tac_defs[s_id], key=lambda x: x[1])],
                )
                for s_id in sorted(tac_block_stmts[block_id], key=stmt_sort_key)
            ]
            blocks[block_id] = Block(block_id, statements)
        except:
            __import__("pdb").set_trace()

    for block in blocks.values():
        block.predecessors = [blocks[pred] for pred in tac_block_pred[block.ident]]
        block.successors = [blocks[succ] for succ in tac_block_succ[block.ident]]

    for block in blocks.values():
        block.predecessors = [blocks[pred] for pred in tac_block_pred[block.ident]]
        block.successors = [blocks[succ] for succ in tac_block_succ[block.ident]]

    functions: Mapping[str, Function] = {}

    for (block_id,) in load_csv(local_path + "IRFunctionEntry.csv"):
        func_id = tac_block_function[block_id]
        high_level_name = (
            "fallback()"
            if tac_func_id_to_public.get(func_id, "_") == "0x0"
            else tac_high_level_func_name[func_id]
        )
        formals = [
            var for var, _ in sorted(tac_formal_args[func_id], key=lambda x: x[1])
        ]

        functions[func_id] = Function(
            func_id,
            high_level_name,
            blocks[block_id],
            func_id in tac_func_id_to_public or func_id == "0x0",
            formals,
        )

    return blocks, functions


def get4bytesinfo(selector):
    url = f"https://www.4byte.directory/api/v1/signatures/?format=json&hex_signature={selector}"
    response = requests.get(url).json()
    if len(response["results"]) != 0:
        return response["results"][-1]["text_signature"]
    else:
        return "UNKNOWN"


def call_info_dot(nodeMap: Dict[str, Call_Node], contract_addr, contract_func):
    content = ""
    content += "digraph{\n"

    for _, node in nodeMap.items():
        # add entry node
        if node.ident == "ENTRY":
            label = "ENTRY\n"
            label += f"contract_addr: {node.addr}\n"
            label += f"func_sig: {contract_func}\n"
            content += f'callsite_ENTRY[label="{label}"];\n'
        elif node.ident == "EXIT":
            label = "EXIT\n"
            content += f'callsite_EXIT[label="{label}"];\n'
        else:
            label = f"callsite({node.calltype}): {node.ident}\n"
            label += f"call_addr: {node.addr}\n"
            if node.addr == "private_call":
                temp_selector = node.selector
                node.selector_name = node.selector
            else:
                temp_selector = get4bytesinfo(node.selector)
                temp_selector = (
                    node.selector if temp_selector == "UNKNOWN" else temp_selector
                )
                if temp_selector != "UNKNOWN":
                    node.selector_name = temp_selector
                else:
                    node.selector_name = node.selector
            label += f"selector: {temp_selector}\n"
            if len(node.tokenInfo) > 0:
                for idx, info in enumerate(node.tokenInfo):
                    label += f"token flow({idx + 1}): {info}"
            content += f'callsite_{node.ident}[label="{label}"];\n'
    for _, node in nodeMap.items():
        for son in node.successors:
            content += f"callsite_{node.ident} -> callsite_{son.ident};\n"
        for ret in node.ret2Arg:
            content += f'callsite_{ret} -> callsite_{node.ident}[color="red"];\n'

    content += "}\n"

    if not os.path.exists("./dots"):
        os.makedirs("./dots")

    if not os.path.exists(f"./dots/{contract_addr}"):
        os.makedirs(f"./dots/{contract_addr}")

    with open(f"./dots/{contract_addr}/{contract_func}.dot", "w") as f:
        f.write(content)


# ==================================================================================

parser = argparse.ArgumentParser()
parser.add_argument(
    "-ch", "--chain", help="The chain to which the contract is deployed"
)
parser.add_argument(
    "-b",
    "--contract_bytecode",
    help="acquire the contract bytecode(hex format)",
    type=str,
)
parser.add_argument(
    "-dt",
    "--dot",
    help="generate contract code dot diagram",
    action="store_true",
)

args = parser.parse_args()

if not args.chain or not args.contract_bytecode:
    parser.print_help()
    exit(1)

if __name__ == "__main__":
    contract = Contract(args.chain, args.contract_bytecode, True)
    contract.analyze_contract()
