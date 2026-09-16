rule Ransom_MSIL_Cryptolocker_PDA_MTB_7{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 } 		$a_81_1 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}