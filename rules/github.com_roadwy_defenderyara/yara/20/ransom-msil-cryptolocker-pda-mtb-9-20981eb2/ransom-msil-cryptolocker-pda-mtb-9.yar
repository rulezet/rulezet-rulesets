rule Ransom_MSIL_Cryptolocker_PDA_MTB_9{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } 		$a_81_1 = {2e 5b 43 72 69 6d 73 6f 6e 77 61 72 65 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68 5d } 		$a_81_2 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_3 = {49 4e 46 4f 2e 68 74 61 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}