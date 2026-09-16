rule Win_Trojan_Delf_1467
{
strings:
	$a0 = { 55681f4d400064ff30648920ba344d40008d8520feffffe8b3dcffff8d8520feffffe844daffffe86bd9ffff8d45fc8b1580864000e82debffff8b45fce8b9ecffff }


condition:
	$a0
}