# HSSI ethernet fecmode #

## SYNOPSIS ##
```console
hssifecmode [-h] [--pcie-address PCIE_ADDRESS, -P PCIE_ADDRESS] --mode [{no,rs}]
```

## DESCRIPTION ##
The ```hssifecmode```  tool select ethernet fecmode.


### OPTIONAL ARGUMENTS ##

`-h, --help`

  Prints usage information

`--pcie-address PCIE_ADDRESS, -P PCIE_ADDRESS`

  The PCIe address of the desired fpga  in ssss:bb:dd.f format. sbdf of device to program (e.g. 04:00.0 or 0000:04:00.0). Optional when one device in system.


`--mode [{no,rs}]`

  Ethernet enable or disable loopback.
  
## EXAMPLES ##

`hssifecmode --pcie-address  0000:04:00.0 --mode rs`

  Select ethernet RS-FEC mode
 
 
`hssifecmode --pcie-address  0000:04:00.0 --mode no`

  Select ethernet NO-FEC mode


## Revision History ##
