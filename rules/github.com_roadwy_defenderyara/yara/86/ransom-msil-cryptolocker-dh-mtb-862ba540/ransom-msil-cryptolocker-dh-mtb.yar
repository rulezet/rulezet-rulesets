rule Ransom_MSIL_CryptoLocker_DH_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 06 00 00 "
		
	strings :
		$a_81_0 = {50 6f 76 6c 73 6f 6d 77 61 72 65 } 		$a_81_1 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 } 		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_3 = {5f 45 6e 63 72 79 70 74 65 64 24 } 		$a_81_4 = {50 61 79 4d 33 } 		$a_81_5 = {55 6d 46 7a 62 32 31 33 59 58 4a 6c 4d 69 34 77 4a 41 3d 3d } 	condition:
		((#a_81_0  & 1)*40+(#a_81_1  & 1)*40+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5) >=55
 
}