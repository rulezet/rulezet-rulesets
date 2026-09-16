rule Trojan_Win32_BunituCrypt_RM_MTB_14{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 10 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } 		$a_03_1 = {2d 00 10 00 00 [0-05] 83 45 [0-05] 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}