rule Ransom_MSIL_Filecoder_ARAD_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 4f 4c 49 4e 20 52 41 4e 53 4f 4d 57 41 52 45 } 		$a_80_1 = {66 75 63 6b 75 6e 65 73 5f 66 61 63 65 } 		$a_80_2 = {62 69 6e 5c 52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 50 59 2e 65 78 65 } 		$a_01_3 = {5c 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 46 69 6c 65 73 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6f 6c 69 6e 77 61 72 65 2e 70 64 62 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}