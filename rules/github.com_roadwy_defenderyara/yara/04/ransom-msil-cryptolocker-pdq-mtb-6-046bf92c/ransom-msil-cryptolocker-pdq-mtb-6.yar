rule Ransom_MSIL_Cryptolocker_PDQ_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } 		$a_81_1 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 4e 61 6d 65 } 		$a_81_2 = {45 6e 63 72 79 70 74 65 64 4b 65 79 } 		$a_81_3 = {43 6f 75 6c 64 20 6e 6f 74 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 20 63 6f 70 79 } 		$a_81_4 = {4f 50 45 4e 5f 4d 45 5f 54 4f 5f 52 45 53 54 4f 52 45 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}