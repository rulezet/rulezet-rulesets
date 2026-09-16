rule Win_Trojan_Oksana_1
{
strings:
	$a0 = { 5f04bfb2062bfe8bcf2e8a0434aa2e880446e2f5be0500bf59022bfe8bcf2e8a0434aa2e880446 }


condition:
	$a0
}