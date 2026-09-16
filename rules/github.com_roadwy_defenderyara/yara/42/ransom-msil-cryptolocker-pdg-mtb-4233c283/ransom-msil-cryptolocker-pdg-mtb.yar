rule Ransom_MSIL_Cryptolocker_PDG_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } 		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } 		$a_81_3 = {41 45 53 5f 45 6e 63 72 79 70 74 } 		$a_81_4 = {5a 65 72 30 42 79 74 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}