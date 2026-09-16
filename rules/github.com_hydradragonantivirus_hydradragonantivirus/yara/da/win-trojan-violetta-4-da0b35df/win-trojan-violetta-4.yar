rule Win_Trojan_Violetta_4
{
strings:
	$a0 = { e8dfff81f9c6077d03eb6f90b42ac606 }


condition:
	$a0
}