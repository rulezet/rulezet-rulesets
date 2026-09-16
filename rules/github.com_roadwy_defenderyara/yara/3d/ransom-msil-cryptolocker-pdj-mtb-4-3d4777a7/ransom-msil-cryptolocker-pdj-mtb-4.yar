rule Ransom_MSIL_Cryptolocker_PDJ_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } 		$a_81_2 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } 		$a_81_3 = {2e 65 6e 63 72 79 70 74 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}