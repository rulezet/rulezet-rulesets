rule Trojan_Win32_Raccrypt_GT_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 ?? 75 } 		$a_02_1 = {25 bb 52 c0 5d 8b [0-06] 8b [0-04] c1 ?? 04 03 [0-08] c1 [0-01] 05 03 [0-28] 8b 45 ?? 29 45 ?? 81 ?? 47 86 c8 61 [0-05] 0f 85 } 		$a_00_2 = {33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}