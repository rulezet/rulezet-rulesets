rule Trojan_Win32_Raccoon_M_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 [0-04] 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 [0-04] 01 08 c3 } 		$a_03_1 = {33 f6 81 3d ?? ?? ?? ?? 34 01 00 00 } 		$a_00_2 = {8a 94 01 3b 2d 0b 00 88 14 30 40 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}