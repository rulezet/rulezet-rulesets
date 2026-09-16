rule Win_Trojan_Ufa_1
{
strings:
	$a0 = { 7e3fb090fcaab0e8aa8b46172d0400ab8d463f894619c7 }


condition:
	$a0
}