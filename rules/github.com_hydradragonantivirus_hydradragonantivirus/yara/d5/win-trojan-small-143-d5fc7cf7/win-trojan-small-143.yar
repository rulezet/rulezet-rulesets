rule Win_Trojan_Small_143
{
strings:
	$a0 = { 10008ec0f6e09c0e5052b97d008bf88bf0f3a4ea1a011000971e078bcc80ed02f3a48ed9a186003bc17413a37f02 }


condition:
	$a0
}