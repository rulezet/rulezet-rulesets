rule Win_Trojan_Orion_2
{
strings:
	$a0 = { 3005b906015133c08ec0f3a406b85a }


condition:
	$a0
}