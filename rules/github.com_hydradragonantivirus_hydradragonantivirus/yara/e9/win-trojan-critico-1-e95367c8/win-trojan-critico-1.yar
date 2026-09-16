rule Win_Trojan_Critico_1
{
strings:
	$a0 = { e800005d81ed0500b88888cd213d05ca7517b90e00fc0e1fbeb7038bfe03f5f3a4060e07ba970052cbb302b80158 }


condition:
	$a0
}