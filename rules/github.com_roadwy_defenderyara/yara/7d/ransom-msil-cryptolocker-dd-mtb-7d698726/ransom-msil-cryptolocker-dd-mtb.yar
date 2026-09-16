rule Ransom_MSIL_CryptoLocker_DD_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_1 = {52 61 6e 73 6f 6d } 		$a_81_2 = {41 45 53 5f 45 6e 63 72 79 70 74 } 		$a_81_3 = {45 6e 63 72 79 70 74 69 6f 6e 46 69 6c 65 } 		$a_81_4 = {44 45 43 52 59 50 54 20 46 49 4c 45 53 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}