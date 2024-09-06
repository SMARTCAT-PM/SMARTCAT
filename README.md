# SMARTCAT

## Description
Identifying Price Manipulation Attack Contracts on Bytecode Level.

## Usage

- install [gigahorse-toolchain](gigahorse-toolchain/README.md)
- python >= 3.8



Run `./tools/gigahorse-toolchain/pm_detector.py`
```shell
$ python3 pm_detector.py -ch eth -b 0xc6028a9Fa486F52efd2B95B949AC630d287CE0aF -dt
```

tool usage :

```shell
usage: pm_detector.py [-h] [-ch CHAIN] [-b CONTRACT_BYTECODE] [-dt]

options:
  -h, --help            show this help message and exit
  -ch CHAIN, --chain CHAIN
                        The chain to which the contract is deployed
  -b CONTRACT_BYTECODE, --contract_bytecode CONTRACT_BYTECODE
                        acquire the contract bytecode(hex format)
  -dt, --dot            generate contract code dot diagram
```

## Datasets
`/dataset` includes the following:

- `PM_attack.csv`: 72 price manipulation attack contracts in $\mathcal{D}_{G1}$.
- `benign_contract.csv`: 8000 benign contracts in  $\mathcal{D}_{G2}$.
- `/ak_address`: Bytecode files of attack contracts collected during the experiment.