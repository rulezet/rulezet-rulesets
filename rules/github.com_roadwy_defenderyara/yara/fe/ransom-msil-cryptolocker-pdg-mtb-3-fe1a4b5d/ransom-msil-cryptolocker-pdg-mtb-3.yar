rule Ransom_MSIL_Cryptolocker_PDG_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 6e 6e 61 62 65 6c 6c 65 2e 65 78 65 } 		$a_81_1 = {41 63 74 69 6f 6e 45 6e 63 72 79 70 74 } 		$a_81_2 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } 		$a_81_3 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } 		$a_81_4 = {47 65 74 46 69 6c 65 73 } 		$a_81_5 = {43 46 41 4c 20 48 61 63 6b } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}