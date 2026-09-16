rule Win_Trojan_Trojan_235
{
strings:
	$a0 = { 19aa30b88fbd230397e2115fe85f7219315ffd80e89f30ecc63334e510b8fd802eed036219d82e17 }


condition:
	$a0
}