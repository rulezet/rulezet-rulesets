rule Ransom_MSIL_Cryptolocker_PDM_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5f 45 6e 63 72 79 70 74 65 64 24 } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_2 = {63 6f 76 69 64 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_81_3 = {77 6f 72 6d 5f 73 68 69 65 6c 64 } 		$a_81_4 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}