rule Ransom_MSIL_Cryptolocker_PDL_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 } 		$a_81_1 = {72 61 6e 73 6f 6d 2e 6a 70 67 } 		$a_81_2 = {2e 43 72 79 70 74 65 64 } 		$a_81_3 = {4e 6f 20 66 69 6c 65 73 20 64 65 63 72 79 70 74 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}