rule Ransom_MSIL_Cryptolocker_PDQ_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 75 6d 6d 79 52 61 6e 73 6f 6d } 		$a_81_1 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } 		$a_81_2 = {41 45 53 5f 45 6e 63 72 79 70 74 } 		$a_81_3 = {2e 6c 6f 63 6b 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}