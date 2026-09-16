rule Ransom_MSIL_Cryptolocker_PDD_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 72 61 70 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_81_1 = {51 33 4a 68 63 48 4e 76 62 58 64 68 63 6d 55 6b } 		$a_81_2 = {47 65 74 46 69 6c 65 73 } 		$a_81_3 = {45 6e 63 72 79 70 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}