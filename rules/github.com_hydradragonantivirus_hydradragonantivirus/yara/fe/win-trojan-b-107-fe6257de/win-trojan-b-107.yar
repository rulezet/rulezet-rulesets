rule Win_Trojan_B_107
{
strings:
	$a0 = { fb0e1f0e07bead7dbf007cfca4a5b402b00abb007e }


condition:
	$a0
}