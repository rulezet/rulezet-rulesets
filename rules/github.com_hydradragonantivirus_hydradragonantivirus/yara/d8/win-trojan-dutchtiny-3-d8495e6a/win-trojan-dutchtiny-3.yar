rule Win_Trojan_DutchTiny_3
{
strings:
	$a0 = { 1fb43fcd218bf2803c4d741cb002e8cfff97b97e00b4 }


condition:
	$a0
}