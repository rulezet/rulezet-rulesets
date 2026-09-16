rule Ransom_MSIL_CryptoLocker_DE_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 6f 4c 6f 63 6b 65 72 } 		$a_81_1 = {45 6e 63 72 79 70 74 65 64 } 		$a_81_2 = {2e 6c 6f 63 6b 65 64 } 		$a_81_3 = {46 69 6c 65 73 20 44 65 63 72 79 70 74 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}