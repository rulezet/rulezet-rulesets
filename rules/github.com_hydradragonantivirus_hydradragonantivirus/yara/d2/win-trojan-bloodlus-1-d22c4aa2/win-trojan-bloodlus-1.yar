rule Win_Trojan_Bloodlus_1
{
strings:
	$a0 = { 0125ba6001cd21b003cd21eb03900000e80300eb47900e }


condition:
	$a0
}