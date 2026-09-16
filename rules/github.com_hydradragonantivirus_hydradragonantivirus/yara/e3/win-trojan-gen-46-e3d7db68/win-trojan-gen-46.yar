rule Win_Trojan_Gen_46
{
strings:
	$a0 = { 06f004f3a426c606f204cb5f07c3 }


condition:
	$a0
}