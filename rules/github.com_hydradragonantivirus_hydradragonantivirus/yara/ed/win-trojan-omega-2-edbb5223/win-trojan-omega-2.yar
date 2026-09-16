rule Win_Trojan_Omega_2
{
strings:
	$a0 = { 7244b440b903008d562bcd217238b440b9b501 }


condition:
	$a0
}