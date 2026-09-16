rule Win_Trojan_Albania_1
{
strings:
	$a0 = { 740c807cfe3b7406aae803000e1fc356511e060e1f }


condition:
	$a0
}