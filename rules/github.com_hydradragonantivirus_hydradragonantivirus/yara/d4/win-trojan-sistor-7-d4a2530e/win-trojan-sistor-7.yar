rule Win_Trojan_Sistor_7
{
strings:
	$a0 = { 90e9000050061ee800005e81ee06002e8b84f9008cc203c20510002e8984f900b430cd21 }


condition:
	$a0
}