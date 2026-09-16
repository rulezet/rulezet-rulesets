rule Ransom_MSIL_Cryptolocker_PDG_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 63 72 79 70 74 65 64 } 		$a_81_1 = {2e 6c 6f 63 6b 65 64 } 		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } 		$a_81_3 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } 		$a_81_4 = {62 6c 6f 63 6b 79 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}