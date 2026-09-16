rule Win_Trojan_VGEN_14
{
strings:
	$a0 = { b447b200be1302cd21b44e2ec60600d001e81e00e89e00b44e2ec60600d000e81000e89000b409bafb01cd21c356 }


condition:
	$a0
}