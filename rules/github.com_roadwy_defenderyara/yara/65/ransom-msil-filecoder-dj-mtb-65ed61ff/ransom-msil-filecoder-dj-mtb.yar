rule Ransom_MSIL_Filecoder_DJ_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 45 50 4c 41 43 45 5f 43 4f 4d 4d 41 4e 44 5f 4c 49 4e 45 } 		$a_81_1 = {5c 73 79 73 74 65 6d 33 32 5c 63 6d 73 74 70 2e 65 78 65 } 		$a_81_2 = {43 4d 53 54 50 42 79 70 61 73 73 } 		$a_81_3 = {47 65 74 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 } 		$a_81_4 = {69 67 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}