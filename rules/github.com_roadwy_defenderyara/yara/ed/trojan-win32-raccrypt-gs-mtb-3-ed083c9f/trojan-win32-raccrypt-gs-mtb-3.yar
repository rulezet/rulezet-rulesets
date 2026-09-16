rule Trojan_Win32_Raccrypt_GS_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {36 23 01 00 8b 0d [0-04] 88 04 0f 81 3d [0-04] 66 0c 00 00 } 		$a_00_1 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 } 		$a_00_2 = {8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}