rule Ransom_MSIL_Filecoder_DA_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 } 		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_2 = {53 43 5f 52 61 6e 73 6f 6d } 		$a_81_3 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}