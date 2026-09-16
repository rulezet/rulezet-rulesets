rule Ransom_MSIL_CryptoLocker_DA_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } 		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 		$a_81_2 = {64 65 73 6b 74 6f 70 2e 69 6e 69 } 		$a_81_3 = {50 61 73 73 77 6f 72 64 } 		$a_81_4 = {31 32 33 34 35 36 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}