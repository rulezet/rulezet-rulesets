rule Trojan_Win32_Gozi_GS_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 8d 52 01 a3 [0-04] 8a 44 17 ff 88 42 ff 8b 35 [0-04] 8d 46 ?? 03 c5 89 44 24 ?? 85 c9 75 } 		$a_02_1 = {2b c8 2b ce 89 0d [0-04] 8b 0d [0-04] 8b 84 11 [0-04] 05 [0-04] a3 [0-04] 89 84 11 [0-04] 83 c2 04 a1 [0-04] 8b 35 [0-04] 83 c0 ?? 03 c6 a3 [0-04] 81 fa [0-04] 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}