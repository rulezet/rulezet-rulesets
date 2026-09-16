rule Win_Trojan_Baloo_2
{
strings:
	$a0 = { 01ba6903cd217303e9f4fec3b4572e8b1e2f03cd217303e9e5fec3b4402e8b1e2f03cd218c }


condition:
	$a0
}