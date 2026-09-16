rule Win_Trojan_Pizelun_1
{
strings:
	$a0 = { b89e46bf380101f7baf40d01f2310547d1c039d775 }


condition:
	$a0
}