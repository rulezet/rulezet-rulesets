rule Trojan_Win32_TrickBotCrypt_EP_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4c 24 24 89 8c 24 94 00 00 00 83 f5 4d 89 6c 24 28 89 ac 24 98 00 00 00 43 89 5c 24 2c 3b 9c 24 80 00 00 00 0f 8c 23 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}