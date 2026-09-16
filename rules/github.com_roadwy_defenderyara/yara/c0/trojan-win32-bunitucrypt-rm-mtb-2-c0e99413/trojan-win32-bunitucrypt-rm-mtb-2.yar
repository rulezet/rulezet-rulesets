rule Trojan_Win32_BunituCrypt_RM_MTB_2{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b ?? ?? ?? ?? ?? 0f } 		$a_03_1 = {03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a 00 e8 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}