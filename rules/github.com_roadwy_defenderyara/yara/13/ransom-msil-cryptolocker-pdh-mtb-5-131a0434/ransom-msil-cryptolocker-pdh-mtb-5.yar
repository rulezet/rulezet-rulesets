rule Ransom_MSIL_Cryptolocker_PDH_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 28 63 6f 75 6e 74 3a 20 6e 29 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } 		$a_81_2 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 43 6f 75 6e 74 } 		$a_81_3 = {46 69 6c 65 45 6e 63 72 79 70 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}