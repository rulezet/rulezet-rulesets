rule Ransom_MSIL_Cryptolocker_PDD_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 41 72 65 20 73 61 66 65 6c 79 20 45 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {72 61 6e 73 6f 6d 2e 6a 70 67 } 		$a_81_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } 		$a_81_3 = {2e 6f 6e 69 6f 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}