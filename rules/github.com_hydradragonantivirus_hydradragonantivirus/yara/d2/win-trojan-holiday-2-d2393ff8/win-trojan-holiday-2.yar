rule Win_Trojan_Holiday_2
{
strings:
	$a0 = { 7403e9b702e8150352b42acd2180fe03750880fa03 }


condition:
	$a0
}