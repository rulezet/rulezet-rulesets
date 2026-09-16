rule Ransom_MSIL_Cryptolocker_PDH_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 66 69 6c 65 73 20 64 65 6c 65 74 65 64 } 		$a_81_1 = {59 6f 75 72 20 46 69 6c 65 73 20 77 65 72 65 20 64 65 6c 65 74 65 64 } 		$a_81_2 = {63 72 79 70 74 5f 65 6e 67 69 6e 65 } 		$a_81_3 = {65 6e 63 72 79 70 74 65 64 5f 73 6f 75 6e 64 2e 77 61 76 } 		$a_81_4 = {2e 63 72 79 70 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}