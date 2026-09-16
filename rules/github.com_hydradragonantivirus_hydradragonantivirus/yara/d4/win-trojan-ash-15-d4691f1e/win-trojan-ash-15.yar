rule Win_Trojan_Ash_15
{
strings:
	$a0 = { 01bf0001b90400fcf3a4b41a8d96c602cd21b44e8d }


condition:
	$a0
}