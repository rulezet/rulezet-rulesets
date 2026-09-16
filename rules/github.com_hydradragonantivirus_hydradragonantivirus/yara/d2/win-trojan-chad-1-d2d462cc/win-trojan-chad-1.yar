rule Win_Trojan_Chad_1
{
strings:
	$a0 = { b803002bf8897c028b440489058a44068845028bd6b8 }


condition:
	$a0
}