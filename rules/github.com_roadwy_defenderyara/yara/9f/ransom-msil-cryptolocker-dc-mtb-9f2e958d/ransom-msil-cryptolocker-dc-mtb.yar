rule Ransom_MSIL_CryptoLocker_DC_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {58 42 75 6e 64 6c 65 72 54 6c 73 48 65 6c 70 65 72 2e 70 64 62 } 		$a_81_1 = {47 68 6f 73 74 2e 65 78 65 } 		$a_81_2 = {54 68 65 6d 69 64 61 } 		$a_81_3 = {73 68 6f 77 69 6e 73 74 61 6e 63 65 } 		$a_81_4 = {64 65 61 63 74 69 76 61 74 65 } 		$a_81_5 = {53 6c 65 65 70 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}