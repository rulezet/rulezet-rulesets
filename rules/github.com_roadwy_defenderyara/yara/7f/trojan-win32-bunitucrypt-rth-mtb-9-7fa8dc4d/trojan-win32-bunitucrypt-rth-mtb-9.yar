rule Trojan_Win32_BunituCrypt_RTH_MTB_9{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 } 		$a_02_1 = {03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 d7 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 89 18 68 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}