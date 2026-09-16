rule Win_Trojan_Violetta_3
{
strings:
	$a0 = { b9090089dfbe0003fca6750ee2fbeb4a }


condition:
	$a0
}