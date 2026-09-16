rule Ransom_MSIL_Filecoder_DA_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 41 4e 53 4f 4d 5f 46 49 4c 45 4e 41 4d 45 } 		$a_81_1 = {52 41 4e 53 4f 4d 5f 4e 4f 54 45 } 		$a_81_2 = {46 75 63 6b 5f 59 6f 75 } 		$a_81_3 = {52 61 6e 73 6f 6d 77 61 72 65 20 54 65 73 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}