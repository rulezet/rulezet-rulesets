rule Win_Trojan_VGEN_290
{
strings:
	$a0 = { 01bb10012e8107000043434e75f6e800005d81ed13011e060e1f0e078db6cb018dbec301a5a5a5a5c686760302b4 }


condition:
	$a0
}