rule Win_Trojan_Fuga_1
{
strings:
	$a0 = { cd213d05ca7517b90e00fc0e1fbebb038bfe03f5f3 }


condition:
	$a0
}