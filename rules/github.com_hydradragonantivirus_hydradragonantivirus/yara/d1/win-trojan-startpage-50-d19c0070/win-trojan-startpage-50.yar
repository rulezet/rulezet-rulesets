rule Win_Trojan_Startpage_50
{
strings:
	$a0 = { 687474703a2f2f36362e3130332e3135332e3135382f636f6f6c2f696e666f2e74787400 }


condition:
	$a0
}