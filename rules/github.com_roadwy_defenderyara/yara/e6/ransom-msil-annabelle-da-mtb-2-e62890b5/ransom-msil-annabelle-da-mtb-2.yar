rule Ransom_MSIL_Annabelle_DA_MTB_2{
	meta:
		description = "Ransom:MSIL/Annabelle.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 6e 6e 61 62 65 6c 6c 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 		$a_81_1 = {41 6e 6e 61 62 65 6c 6c 65 2e 65 78 65 } 		$a_81_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 		$a_81_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } 		$a_81_4 = {41 63 74 69 6f 6e 45 6e 63 72 79 70 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}