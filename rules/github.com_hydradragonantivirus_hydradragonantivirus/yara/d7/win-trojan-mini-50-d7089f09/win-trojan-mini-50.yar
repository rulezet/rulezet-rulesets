rule Win_Trojan_Mini_50
{
strings:
	$a0 = { 721cba9e00b8023dcd218bd8b92c00 }


condition:
	$a0
}