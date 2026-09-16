rule Win_Trojan_Cinderella_4
{
strings:
	$a0 = { 0e1fbe8a03bf9000ad8905ad894502 }


condition:
	$a0
}