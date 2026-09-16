rule Ransom_MSIL_CryptoLocker_DJ_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 61 70 70 79 57 61 6c 6c 65 74 } 		$a_81_1 = {52 53 41 45 6e 63 72 79 70 74 } 		$a_81_2 = {67 65 74 5f 45 78 74 65 6e 73 69 6f 6e } 		$a_81_3 = {42 49 54 43 4f 49 4e 5f 41 44 44 52 45 53 53 } 		$a_81_4 = {66 75 63 6b 33 36 30 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}