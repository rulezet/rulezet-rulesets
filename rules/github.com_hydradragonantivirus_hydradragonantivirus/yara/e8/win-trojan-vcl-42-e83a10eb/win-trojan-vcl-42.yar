rule Win_Trojan_VCL_42
{
strings:
	$a0 = { b904018134????4646e2f8c3 }


condition:
	$a0
}