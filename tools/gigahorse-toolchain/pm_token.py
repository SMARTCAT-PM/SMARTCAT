from web3 import Web3


class AKToken:
    def __init__(self, tokenAddr=None, tokenName=None) -> None:
        self.tokenAddr = tokenAddr
        self.tokenName = tokenName
        self.stateOrderChain = []


class AKPair:
    def __init__(
        self, chain=None, pair_addr=None, token0: AKToken = None, token1: AKToken = None
    ) -> None:
        self.chain = chain
        self.pairAddr = pair_addr
        self.token0 = token0
        self.token1 = token1
        if self.chain == "bsc":
            self.rpc_url = "https://bsc-dataseed2.defibit.io/"
        elif self.chain == "eth":
            self.rpc_url = (
                "https://mainnet.infura.io/v3/fa3f945546d84dcaa747701c2ce7c6de"
            )

    def GetToken0and1(self):
        contract_address = Web3.to_checksum_address(self.pairAddr)
        contract_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "token0",
                "outputs": [{"name": "", "type": "address"}],
                "type": "function",
            },
            {
                "constant": True,
                "inputs": [],
                "name": "token1",
                "outputs": [{"name": "", "type": "address"}],
                "type": "function",
            },
        ]

        web3 = Web3(Web3.HTTPProvider(self.rpc_url))
        contract = web3.eth.contract(address=contract_address, abi=contract_abi)
        try:
            token0_address = contract.functions.token0().call()
            token1_address = contract.functions.token1().call()
            self.token0 = AKToken(tokenAddr=token0_address)
            self.token1 = AKToken(tokenAddr=token1_address)
            return True
        except Exception as e:
            print("call token0/1 error: ", e)
            print("potential pair address", self.pairAddr)
            # traceback.print_exc()
            return False

    def GetIthToken(self, i, j):
        contract_address = Web3.to_checksum_address(self.pairAddr)
        contract_abi = [
            {
                "name": "coins",
                "outputs": [{"type": "address", "name": ""}],
                "inputs": [{"type": "int128", "name": "arg0"}],
                "constant": True,
                "payable": False,
                "type": "function",
                "gas": 2130,
            }
        ]

        web3 = Web3(Web3.HTTPProvider(self.rpc_url))
        contract = web3.eth.contract(address=contract_address, abi=contract_abi)
        try:
            i_addr = contract.functions.coins(i).call()
            j_addr = contract.functions.coins(j).call()
            self.token0 = AKToken(tokenAddr=i_addr)
            self.token1 = AKToken(tokenAddr=j_addr)
            return True
        except Exception as e:
            print("call token0/1 error: ", e)
            print("potential pair address", self.pairAddr)
            # traceback.print_exc()
            return False


class TokenAction:
    def __init__(
        self,
        ident=None,
        action_type=None,
        caller=None,
        from_address=None,
        to_address=None,
        order_params=None,
        swap_pairaddr=None,
        amountIn=0,
        amountOut=0,
        Value=0,
        selector_name=None,
    ) -> None:
        self.ident = ident
        self.Type = action_type
        self.caller = caller
        self.order_params = order_params
        self.swap_pairaddr = swap_pairaddr
        self.from_address = from_address
        self.to_address = to_address
        self.amountIn = amountIn
        self.amountOut = amountOut
        self.Value = Value
        self.selector_name = selector_name


# -----------------------------------------------------------------------------------
# match specific function signature (especically in swap protocal and erc20 token contract)
# for common case, we just hard match
# -----------------------------------------------------------------------------------

PairSwapSigs = {
    # UniSwap & pancakeSwap
    "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "0x8803dbee": "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
    "0x7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
    "0x4a25d94a": "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
    "0x18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    "0xfb3bdb41": "swapETHForExactTokens(uint256,address[],address,uint256)",
    "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
    "0xb6f9de95": "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)",
    "0x791ac947": "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
    "0x022c0d9f": "swap(uint256,uint256,address,bytes)",
    "0x128acb08": "swap(address,bool,int256,uint160,bytes)",
    # other:
    # ISwapRouter
    "0xc04b8d59": "exactInput((bytes,address,uint256,uint256,uint256))",
    "0x414bf389": "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
    "0xf28c0498": "exactOutput((bytes,address,uint256,uint256,uint256))",
    "0xdb3e2198": "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
    # Curve
    "0x3df02124": "exchange(int128,int128,uint256,uint256)",
    "0xa6417ed6": "exchange_underlying(int128,int128,uint256,uint256)",
    # flash
    "0x490e6cbc": "flash(address,uint256,uint256,bytes)",
}

Addr2Token = {
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "WBNB",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0xdAC17F958D2ee523a2206206994597C13D831ec7": "USDC",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "BUSDC",
}

ERCXXXToken = [
    # erc20
    "0xa9059cbb",
    "0x70a08231",
    "0x23b872dd",
    "0x095ea7b3",
    "0xdd62ed3e",
    "0x313ce567",
    # erc721
    "0x6352211e",
    "0x081812fc",
    "0xa22cb465",
    "0xe985e9c5",
    "0x42842e0e",
    "0xb88d4fde",
    # erc1155
    "0xf242432a",
    "0x2eb2c2d6",
    "0x4e1273f4",
]

FlashAction = ["0x490e6cbc"]

CommonSwapFuncSig = [
    "0x022c0d9f",
    "0x128acb08",
    "0x7ff36ab5",
    "0x18cbafe5",
    "0x9cf68911",
    "0xa6417ed6",
]

BalanceRelated = [
    "balanceOf",
    "getAmountsIn",
    "getAmountsOut",
    "getAmountIn",
    "getAmountOut",
]


PoolAction = [
    "0xe8e33700",
    "0xf305d719",
    "0x02751cec",
    "0x2195995c",
    "0xded9382a",
    "0xaf2979eb",
    "0x5b0d5984",
    "0x38ed1739",
    "0x8803dbee",
    "0x4a25d94a",
    "0xfb3bdb41",
    "0x5c11d795",
    "0xb6f9de95",
    "0x791ac947",
    "0xc04b8d59",
    "0x414bf389",
    "0xf28c0498",
    "0xdb3e2198",
    "0x3df02124",
    "0xbaa2abde",
]

PoolOpAction = [
    "0xe8e33700",
    "0xbaa2abde",
    "0xf305d719",
    "0x02751cec",
    "0x2195995c",
    "0xded9382a",
    "0xaf2979eb",
    "0x5b0d5984",
]

FlashCallback = [
    "0x10d1e85c",
    "0xfa461e33",
    "0xe9cbafb0",
    "0x84800812",
    "0x805814b3",
    "0x175bd654",
    "0xa1d48336",
    "0xeb2021c3",
    "0x7ed1f1dd",
    "0xd5b99797",
    "0x7d0ef197",
    "0xc0452f0a",
    "0x2a77b18b",
    "0x38b0baf1",
    "0x5a13eac1",
    "0x1b390145",
    "0xf04f2707",
    "0x23e30c8b",
    "0x5b3bc4fe",
    "0x485f3994",
]
