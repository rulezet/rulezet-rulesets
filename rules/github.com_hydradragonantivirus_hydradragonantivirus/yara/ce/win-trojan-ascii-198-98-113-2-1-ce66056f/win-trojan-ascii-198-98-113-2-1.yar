rule Win_Trojan_Ascii_198_98_113_2_1
{
strings:
	$a0 = { 3139382e39382e3131332e32 }


condition:
	$a0
}