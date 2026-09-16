rule Ransom_Win32_Crypmod_MK_MTB_2{
	meta:
		description = "Ransom:Win32/Crypmod.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } 		$a_80_1 = {2e 61 76 69 2e 63 73 73 2e 64 6f 63 2e 67 69 66 2e 68 74 6d 2e 6a 70 67 2e 6d 6f 76 2e 6d 70 33 2e 6d 70 34 2e 6d 70 67 2e 70 64 66 2e 70 6e 67 2e 70 70 74 2e 72 61 72 2e 73 76 67 2e 74 78 74 2e 78 6c 73 2e 78 6d 6c 2e 7a 69 70 } 		$a_03_2 = {84 02 0f b6 33 43 45 31 c6 96 0f b6 c0 96 8b 34 b2 c1 e8 ?? 31 f0 39 cd 7c e6 } 		$a_80_3 = {68 69 6a 61 63 6b 65 64 } 		$a_80_4 = {52 45 41 44 4d 45 2e 74 78 74 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_03_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}