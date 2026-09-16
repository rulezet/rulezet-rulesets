rule Ransom_MSIL_CryptoLocker_DB_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 28 63 6f 75 6e 74 3a 20 6e 29 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {66 72 69 65 6e 64 6c 79 2e 63 79 62 65 72 2e 63 72 69 6d 69 6e 61 6c 40 67 6d 61 69 6c 2e 63 6f 6d } 		$a_81_2 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } 		$a_81_3 = {2e 6c 6f 63 6b 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}