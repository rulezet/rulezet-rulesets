rule Win_Trojan_Small_4396
{
strings:
	$a0 = { 50b8ff23420081c00100000001042468 }


condition:
	$a0
}