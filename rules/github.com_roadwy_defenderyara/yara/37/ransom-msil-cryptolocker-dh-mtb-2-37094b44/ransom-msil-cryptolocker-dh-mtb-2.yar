rule Ransom_MSIL_CryptoLocker_DH_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 6f 72 2e 65 78 65 } 		$a_81_1 = {4e 61 6d 61 73 74 65 55 6e 6c 6f 63 6b } 		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 		$a_81_3 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } 		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_5 = {43 6f 6e 66 75 73 65 72 45 78 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}