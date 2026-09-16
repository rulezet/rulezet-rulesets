rule Ransom_MSIL_Cryptolocker_PDA_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 62 43 72 79 20 32 2e 30 } 		$a_81_1 = {41 6c 62 43 72 79 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 		$a_81_2 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } 		$a_81_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}