rule Win_Trojan_Boys_2
{
strings:
	$a0 = { 050300508bf0bf0001b90500fcf3a4 }


condition:
	$a0
}