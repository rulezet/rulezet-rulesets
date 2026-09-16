rule Ransom_MSIL_Cryptolocker_PDH_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {52 61 6e 73 6f 6d 65 54 6f 61 64 } 		$a_81_2 = {50 6f 76 6c 73 6f 6d 77 61 72 65 } 		$a_81_3 = {44 65 63 72 79 70 74 20 46 69 6c 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}