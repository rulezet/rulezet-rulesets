rule Ransom_MSIL_CryptoLocker_DF_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_81_1 = {41 6c 6f 20 4d 69 6e 65 67 61 6d 65 73 20 72 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}