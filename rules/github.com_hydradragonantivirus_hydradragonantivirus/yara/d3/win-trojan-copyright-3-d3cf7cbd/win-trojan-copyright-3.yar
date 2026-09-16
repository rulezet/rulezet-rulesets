rule Win_Trojan_Copyright_3
{
strings:
	$a0 = { feb44bcd213dcdab747f2ea1cf028e }


condition:
	$a0
}