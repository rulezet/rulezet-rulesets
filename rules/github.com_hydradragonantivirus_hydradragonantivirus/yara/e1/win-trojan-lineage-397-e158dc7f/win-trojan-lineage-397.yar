rule Win_Trojan_Lineage_397
{
strings:
	$a0 = { cec9c1ced4a00000ffffffff040000004a756d7000000000ffffffff03000000486f6f00ffffffff030000006b4f6e00ffffffff040000006b4f6666000000004433 }


condition:
	$a0
}