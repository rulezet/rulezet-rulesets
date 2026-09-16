rule Ransom_MSIL_Cryptolocker_PDH_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 53 20 45 6e 63 72 79 70 74 65 72 } 		$a_81_1 = {75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 } 		$a_81_2 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } 		$a_81_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}