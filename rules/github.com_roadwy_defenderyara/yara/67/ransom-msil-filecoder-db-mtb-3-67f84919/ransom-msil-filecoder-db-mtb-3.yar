rule Ransom_MSIL_Filecoder_DB_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 6f 70 73 2c 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } 		$a_81_1 = {53 65 6e 64 20 24 33 30 30 20 77 6f 72 74 68 20 6f 66 20 62 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 3a } 		$a_81_2 = {2e 6c 6f 63 6b 65 64 } 		$a_81_3 = {4d 41 4c 57 41 52 45 2e 70 64 62 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}