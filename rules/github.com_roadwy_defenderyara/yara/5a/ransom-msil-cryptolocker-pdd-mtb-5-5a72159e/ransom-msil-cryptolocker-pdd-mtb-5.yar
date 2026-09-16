rule Ransom_MSIL_Cryptolocker_PDD_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 } 		$a_81_1 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } 		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_3 = {2e 57 65 53 74 20 4e 65 74 20 46 61 6b 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}