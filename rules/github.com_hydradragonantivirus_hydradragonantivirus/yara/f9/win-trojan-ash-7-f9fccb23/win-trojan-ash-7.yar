rule Win_Trojan_Ash_7
{
strings:
	$a0 = { 5d81ed0b018db60401bf0001b90400fcf3a4b41a8d960d02cd21c686380200b44e8db62b028d96070252eb30b4 }


condition:
	$a0
}