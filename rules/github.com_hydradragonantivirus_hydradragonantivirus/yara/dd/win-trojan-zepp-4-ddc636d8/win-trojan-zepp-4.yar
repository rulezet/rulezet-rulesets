rule Win_Trojan_Zepp_4
{
strings:
	$a0 = { c6052495400001e8040b0000c6052495400000e8f80a00005589e581ec000200008dbd00ff }


condition:
	$a0
}