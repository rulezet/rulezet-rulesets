rule Win_Trojan_MPS_OPC_3
{
strings:
	$a0 = { db7441b42ccd213ada73042ad3ebf88adaba8e0203d6b9 }


condition:
	$a0
}