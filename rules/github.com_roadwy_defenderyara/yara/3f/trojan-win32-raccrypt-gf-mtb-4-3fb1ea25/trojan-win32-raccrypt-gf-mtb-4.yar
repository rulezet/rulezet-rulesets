rule Trojan_Win32_Raccrypt_GF_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 ?? 8b 45 ?? 8a 04 08 88 04 39 41 3b 0d } 		$a_02_1 = {8b c6 d3 e8 03 45 ?? 33 45 ?? 2b f8 83 fa ?? 75 ?? ff 15 ?? ?? ?? ?? 25 bb 52 c0 5d } 		$a_02_2 = {33 75 0c 8b 45 08 89 30 5e [0-01] c2 08 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 } 		$a_02_3 = {c1 e0 04 89 01 c3 55 8b ec 83 ec 0c 83 3d ?? ?? ?? ?? 03 56 8b f0 75 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1+(#a_02_2  & 1)*10+(#a_02_3  & 1)*1) >=21
 
}