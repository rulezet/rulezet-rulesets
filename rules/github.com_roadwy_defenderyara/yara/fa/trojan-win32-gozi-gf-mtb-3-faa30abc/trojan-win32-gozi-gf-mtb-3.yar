rule Trojan_Win32_Gozi_GF_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8d 4b ?? 2b c8 1b d6 01 0d [0-04] 8d 48 ff 11 15 [0-04] 0f af d9 8b 4c 24 ?? 8b 39 8a c8 80 e9 ?? 00 0d [0-04] 81 7c 24 [0-05] 75 } 		$a_02_1 = {33 c9 2b e8 1b ce 01 2d [0-04] 0f b6 6c 24 ?? 11 0d [0-04] 4d 0f af 2d [0-04] 8b 4c 24 ?? 83 44 24 ?? 04 81 c7 [0-04] 89 39 8a 4c 24 ?? 02 c8 ff 4c 24 ?? 89 2d [0-04] 89 3d [0-04] 88 4c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}