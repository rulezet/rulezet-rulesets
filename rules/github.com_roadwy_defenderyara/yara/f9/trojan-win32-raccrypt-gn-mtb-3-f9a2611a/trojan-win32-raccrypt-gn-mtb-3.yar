rule Trojan_Win32_Raccrypt_GN_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 32 81 3d ?? ?? ?? ?? 03 02 00 00 90 0a 23 00 a1 ?? ?? ?? ?? 8a 8c 30 ?? ?? ?? ?? 8b 15 } 		$a_02_1 = {8b 4c 24 0c 30 04 31 81 ff 91 05 00 00 90 18 46 3b f7 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}