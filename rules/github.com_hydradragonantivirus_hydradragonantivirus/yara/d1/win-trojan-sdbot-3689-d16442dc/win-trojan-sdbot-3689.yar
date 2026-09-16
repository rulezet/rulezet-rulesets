rule Win_Trojan_SdBot_3689
{
strings:
	$a0 = { 01e231fe34f86d4ceda52eaa2a18febe4028ed85ad269aa518061e0a28c26b09a142b6db9f6f3bb23339b81f5def997400db89e97738d7251574f1f6c2c2dd57d6dfba32f7a576fe2e37c6c221c3 }


condition:
	$a0
}