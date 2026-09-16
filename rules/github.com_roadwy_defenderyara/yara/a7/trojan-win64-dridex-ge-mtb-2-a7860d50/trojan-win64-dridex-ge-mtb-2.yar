rule Trojan_Win64_Dridex_GE_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {44 8b 44 24 ?? 45 89 c2 44 89 d2 44 8b 44 24 ?? 44 8b 4c 24 ?? ff d0 } 		$a_02_1 = {4d 0f af c9 4c 89 8c 24 ?? ?? ?? ?? 45 89 d2 45 89 d1 48 89 54 24 ?? 4c 89 ca 45 89 d9 ff d0 } 		$a_80_2 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } 		$a_80_3 = {72 61 69 73 69 6e 67 6e 35 38 37 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10) >=21
 
}