rule Win_Trojan_AVCS_3
{
strings:
	$a0 = { 018db60d01bfbcf8b91401f3a4bedaf8e865ffb440babcf8b91401cd21b80042e82000b440b903 }


condition:
	$a0
}