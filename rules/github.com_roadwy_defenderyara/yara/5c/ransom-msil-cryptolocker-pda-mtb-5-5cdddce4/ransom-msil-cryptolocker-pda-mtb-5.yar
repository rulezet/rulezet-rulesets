rule Ransom_MSIL_Cryptolocker_PDA_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 61 73 6b 20 4d 61 6e 61 67 65 72 } 		$a_81_1 = {45 6e 63 72 79 70 74 46 69 6c 65 73 } 		$a_81_2 = {47 65 74 42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } 		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_4 = {5f 45 6e 63 72 79 70 74 65 64 24 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}