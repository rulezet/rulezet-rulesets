rule Ransom_MSIL_Cryptolocker_PDL_MTB_7{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 4f 57 5f 43 41 4e 5f 47 45 54 5f 46 49 4c 45 53 5f 42 41 43 4b } 		$a_81_1 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 46 69 6e 69 73 68 65 64 } 		$a_81_2 = {57 68 61 74 20 54 68 65 20 46 75 63 6b } 		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}