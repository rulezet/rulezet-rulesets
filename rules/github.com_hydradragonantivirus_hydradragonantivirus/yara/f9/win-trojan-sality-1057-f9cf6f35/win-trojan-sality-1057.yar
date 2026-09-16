rule Win_Trojan_Sality_1057
{
strings:
	$a0 = { 8a440500[0-2]3007????fec9 }


condition:
	$a0
}