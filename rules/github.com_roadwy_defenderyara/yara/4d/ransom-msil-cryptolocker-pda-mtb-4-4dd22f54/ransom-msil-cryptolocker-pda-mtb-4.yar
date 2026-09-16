rule Ransom_MSIL_Cryptolocker_PDA_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } 		$a_81_1 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 2e 74 78 74 } 		$a_81_2 = {2e 4c 6f 63 6b } 		$a_81_3 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}