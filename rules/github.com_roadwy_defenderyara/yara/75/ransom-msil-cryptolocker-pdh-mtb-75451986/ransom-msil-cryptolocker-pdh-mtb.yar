rule Ransom_MSIL_Cryptolocker_PDH_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {5a 69 67 67 79 20 52 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_1 = {52 65 61 6d 61 69 6e 69 6e 67 20 74 69 6d 65 3a } 		$a_81_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 44 69 73 6b 44 72 69 76 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}