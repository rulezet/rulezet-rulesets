rule Trojan_Win64_Dridex_DK_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 8b d9 0f b6 d2 49 b9 01 01 01 01 01 01 01 01 4c 0f af ca 49 83 f8 10 0f 86 f2 00 00 00 66 49 0f 6e c1 66 0f 60 c0 49 81 f8 80 00 00 00 77 10 } 		$a_00_1 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 10 40 8a 3a 48 8b da 4c 8b c1 40 84 ff } 		$a_80_2 = {6b 64 74 6c 74 64 79 62 69 70 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*3) >=23
 
}