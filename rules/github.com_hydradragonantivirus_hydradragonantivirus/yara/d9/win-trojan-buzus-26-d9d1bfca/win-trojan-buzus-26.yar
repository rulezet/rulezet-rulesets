rule Win_Trojan_Buzus_26
{
strings:
	$a0 = { 558bec83c4f0b8c0251413e8ccf5ffffe8fbfdffffe8e6f0ffff8bc0 }


condition:
	$a0
}