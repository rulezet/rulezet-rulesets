rule Ransom_MSIL_Filecoder_DB_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } 		$a_81_1 = {53 74 69 6c 6c 20 6c 6f 63 6b 65 64 2e 20 4a 75 73 74 20 70 61 79 2e } 		$a_81_2 = {55 6e 6c 6f 63 6b 65 64 2e 20 54 68 61 6e 6b 73 20 66 6f 72 20 70 61 79 69 6e 67 2e } 		$a_81_3 = {50 34 59 4d 45 } 		$a_81_4 = {70 61 73 73 77 6f 72 64 2e 74 78 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}