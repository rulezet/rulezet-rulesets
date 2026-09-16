rule Trojan_Win32_Stealerc_AMBH_MTB_3{
	meta:
		description = "Trojan:Win32/Stealerc.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 74 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 54 24 1c 89 54 24 1c 8b 44 24 1c 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 30 81 3d ?? ?? ?? ?? be 01 00 00 } 		$a_03_1 = {8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 54 24 18 89 54 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 2c 81 3d ?? ?? ?? ?? be 01 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}