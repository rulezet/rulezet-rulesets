rule Win_Trojan_Gen_78
{
strings:
	$a0 = { c00106e00501064806a3140033c08e }


condition:
	$a0
}