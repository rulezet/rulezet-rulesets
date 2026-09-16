rule Win_Trojan_Virdem_1
{
strings:
	$a0 = { 80008d3ebf03b92000f3a4b8000026 }


condition:
	$a0
}