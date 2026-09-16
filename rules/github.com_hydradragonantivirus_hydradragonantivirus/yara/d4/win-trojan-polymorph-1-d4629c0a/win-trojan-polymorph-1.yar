rule Win_Trojan_Polymorph_1
{
strings:
	$a0 = { 0e1fb90300cd2172ddccb8004233c933d2cd21b4400e1fbada005b03d3b9030053bed40003f38b }


condition:
	$a0
}