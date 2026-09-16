rule Trojan_Win32_BunituCrypt_RM_MTB_15{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 b0 8a a5 08 00 [0-08] 00 00 00 } 		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}