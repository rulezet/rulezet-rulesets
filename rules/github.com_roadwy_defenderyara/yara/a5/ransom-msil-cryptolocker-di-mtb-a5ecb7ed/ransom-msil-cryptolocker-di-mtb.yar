rule Ransom_MSIL_CryptoLocker_DI_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {43 72 79 70 74 6f 4c 6f 63 6b 65 72 } 		$a_81_2 = {62 69 63 74 6f 69 6e 73 } 		$a_81_3 = {2f 43 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}