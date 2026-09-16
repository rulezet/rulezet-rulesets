rule Win_Trojan_Trojan_171
{
strings:
	$a0 = { 646561643a783a313a313a616e6172636865653a2f3a2f62696e2f7368 }


condition:
	$a0
}