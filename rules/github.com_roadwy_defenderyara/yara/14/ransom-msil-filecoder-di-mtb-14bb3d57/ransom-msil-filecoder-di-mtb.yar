rule Ransom_MSIL_Filecoder_DI_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } 		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_2 = {70 61 73 73 77 6f 72 64 31 32 33 } 		$a_81_3 = {53 43 5f 52 61 6e 73 6f 6d } 		$a_81_4 = {46 69 6c 65 43 72 79 70 74 65 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}