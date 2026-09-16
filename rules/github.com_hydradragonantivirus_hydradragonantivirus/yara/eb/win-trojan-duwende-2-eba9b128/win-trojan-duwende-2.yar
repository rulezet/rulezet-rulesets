rule Win_Trojan_Duwende_2
{
strings:
	$a0 = { 72589a7247653ba99d6c598a73ca986c5992ee9f6c5d98efdb6c5d9eee8e2ada6c5d9bee989e92721b9a306c598aee9b }


condition:
	$a0
}