rule Win_Trojan_Packed_12
{
strings:
	$a0 = { 807c24080160eb }


condition:
	$a0
}