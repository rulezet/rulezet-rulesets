rule Trojan_Win32_BunituCrypt_RT_MTB_14{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 4f 0c 00 00 } 		$a_03_1 = {03 d8 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 4f 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}