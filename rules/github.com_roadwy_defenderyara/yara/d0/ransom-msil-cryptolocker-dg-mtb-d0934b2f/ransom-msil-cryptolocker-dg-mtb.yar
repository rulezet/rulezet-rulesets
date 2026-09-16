rule Ransom_MSIL_CryptoLocker_DG_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } 		$a_81_1 = {53 74 61 72 74 45 6e 63 72 79 70 74 69 6f 6e 50 72 6f 63 65 73 73 } 		$a_81_2 = {4e 61 6d 61 73 74 65 55 6e 6c 6f 63 6b } 		$a_81_3 = {46 69 6c 65 45 6e 63 72 79 70 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}