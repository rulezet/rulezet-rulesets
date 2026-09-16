rule Ransom_MSIL_Cryptolocker_PDQ_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {41 45 53 5f 45 6e 63 72 79 70 74 } 		$a_81_2 = {62 69 74 63 6f 69 6e 73 } 		$a_81_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}