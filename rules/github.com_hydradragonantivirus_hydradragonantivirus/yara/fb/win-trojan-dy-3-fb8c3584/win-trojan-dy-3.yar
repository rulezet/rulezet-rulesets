rule Win_Trojan_Dy_3
{
strings:
	$a0 = { 803e00005a7403e99600812e030012007303e98400a11200 }


condition:
	$a0
}