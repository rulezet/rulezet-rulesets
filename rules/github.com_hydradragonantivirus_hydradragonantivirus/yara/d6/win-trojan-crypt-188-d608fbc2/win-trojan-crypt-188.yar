rule Win_Trojan_Crypt_188
{
strings:
	$a0 = { 575f565683c404578bfef7d787f75f83c4048b7424fce80d6a010056f7de5e0000000000000000 }


condition:
	$a0
}