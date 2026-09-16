rule Win_Trojan_Violetta_6
{
strings:
	$a0 = { b0f1cd21b9090089dfbe0003fca6 }


condition:
	$a0
}