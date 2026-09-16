rule Win_Trojan_Plastique_1
{
strings:
	$a0 = { cc599d2eff2e34009ccc2eff0603 }


condition:
	$a0
}