rule Ransom_MSIL_Cryptolocker_PDD_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 69 72 62 77 61 72 65 } 		$a_81_1 = {2e 62 69 72 62 62 } 		$a_81_2 = {72 61 6e 73 6f 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 		$a_81_3 = {44 65 63 72 79 70 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}