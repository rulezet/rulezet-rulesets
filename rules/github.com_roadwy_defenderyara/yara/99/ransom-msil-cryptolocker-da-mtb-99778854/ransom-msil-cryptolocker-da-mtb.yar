rule Ransom_MSIL_CryptoLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } 		$a_81_1 = {42 69 74 63 6f 69 6e } 		$a_81_2 = {2e 65 6e 63 72 79 70 74 65 64 } 		$a_81_3 = {72 61 6e 73 6f 6d 77 61 72 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}