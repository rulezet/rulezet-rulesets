rule Win_Trojan_N_109
{
strings:
	$a0 = { b9040333f6a13e013104464681fe2e01750481c678004975ef }


condition:
	$a0
}