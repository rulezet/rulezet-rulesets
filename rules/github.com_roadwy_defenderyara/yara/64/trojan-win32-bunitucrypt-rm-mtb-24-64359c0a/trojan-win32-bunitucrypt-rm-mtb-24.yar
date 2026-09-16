rule Trojan_Win32_BunituCrypt_RM_MTB_24{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 05 8a a5 08 00 03 45 ?? 03 d8 68 61 1e 00 00 6a } 		$a_03_1 = {68 61 1e 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}