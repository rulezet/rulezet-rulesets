rule Ransom_MSIL_Cryptolocker_PDD_MTB_8{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 69 6f 6e 20 50 72 6f 67 72 61 6d 20 66 6f 72 20 43 72 79 70 74 6f 6c 6f 63 6b 65 72 } 		$a_81_1 = {63 72 79 70 74 6f 6c 6f 63 6b 65 72 2e 65 78 65 } 		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_4 = {44 65 62 75 67 67 65 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}