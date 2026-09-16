rule Trojan_Win32_TrickBotCrypt_EE_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 0a 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 55 f8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 45 ec 2b c2 } 		$a_03_1 = {2b c2 2b 05 ?? ?? ?? ?? 8b 55 0c 8b 75 08 8a 0c 0a 32 0c 06 } 		$a_03_2 = {03 c6 03 d0 03 15 ?? ?? ?? ?? 8b 45 0c 88 0c 10 e9 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}