rule Trojan_Win32_Raccrypt_GR_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 56 8b f0 90 18 33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 81 00 a4 36 ef c6 c3 } 		$a_00_1 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 81 00 a4 36 ef c6 c3 } 		$a_02_2 = {25 bb 52 c0 5d 8b [0-02] 8b [0-04] c1 ?? 04 03 [0-06] 33 [0-08] c1 [0-01] 05 03 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5) >=10
 
}