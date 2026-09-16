rule Ransom_MSIL_Filecoder_DB_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 64 65 63 72 79 70 74 65 64 20 6e 6f 77 } 		$a_81_1 = {2e 50 41 54 50 41 54 } 		$a_81_2 = {68 65 61 64 70 61 74 73 20 74 6f 20 67 6f 21 } 		$a_81_3 = {70 61 74 70 61 74 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}