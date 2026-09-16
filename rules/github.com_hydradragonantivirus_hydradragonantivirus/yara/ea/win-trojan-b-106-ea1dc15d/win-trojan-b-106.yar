rule Win_Trojan_B_106
{
strings:
	$a0 = { 0e1f0e07bead7dbf007cfca4a5b402b00abb007eb902 }


condition:
	$a0
}