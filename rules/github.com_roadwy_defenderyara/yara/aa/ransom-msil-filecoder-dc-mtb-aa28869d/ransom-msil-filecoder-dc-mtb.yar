rule Ransom_MSIL_Filecoder_DC_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 5f 5f 5f 5f 5f 54 42 54 54 5f 5f 5f 5f 5f } 		$a_81_1 = {65 6e 63 72 79 70 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 		$a_81_2 = {46 69 6c 65 43 72 79 70 74 } 		$a_81_3 = {47 65 6e 43 55 53 54 4f 4d 41 45 53 4b 65 79 } 		$a_81_4 = {65 6e 63 72 79 70 74 6f 72 2e 70 64 62 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}