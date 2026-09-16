rule Trojan_Win32_TrickBotCrypt_ES_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e4 0f b6 02 0f b6 4d eb 33 c1 8b 55 e4 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e4 88 02 8b 45 e4 03 45 f4 89 45 e4 eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}