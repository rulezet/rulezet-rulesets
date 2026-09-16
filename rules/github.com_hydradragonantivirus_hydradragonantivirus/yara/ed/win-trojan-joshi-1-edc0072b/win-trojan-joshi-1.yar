rule Win_Trojan_Joshi_1
{
strings:
	$a0 = { 022d2100bf0000be007c03f003f8b979012bc8 }


condition:
	$a0
}