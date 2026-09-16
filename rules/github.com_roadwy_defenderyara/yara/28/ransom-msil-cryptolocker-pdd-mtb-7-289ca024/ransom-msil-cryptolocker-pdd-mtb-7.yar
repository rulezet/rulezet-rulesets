rule Ransom_MSIL_Cryptolocker_PDD_MTB_7{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {50 75 72 63 68 61 73 65 20 42 69 74 63 6f 69 6e } 		$a_81_2 = {44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 } 		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 61 6c 6c 20 6e 6f 77 20 64 65 63 72 79 70 74 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}