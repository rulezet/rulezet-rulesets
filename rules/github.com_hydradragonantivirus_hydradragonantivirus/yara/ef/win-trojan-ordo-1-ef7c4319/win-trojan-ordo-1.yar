rule Win_Trojan_Ordo_1
{
strings:
	$a0 = { 0200550000000100ffff210300000c020000040000002103 }


condition:
	$a0
}