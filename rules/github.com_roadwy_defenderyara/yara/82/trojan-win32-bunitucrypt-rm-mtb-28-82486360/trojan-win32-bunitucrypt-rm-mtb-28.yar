rule Trojan_Win32_BunituCrypt_RM_MTB_28{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 } 		$a_03_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 83 ?? ?? 04 83 ?? ?? 04 8b ?? ?? 3b } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}