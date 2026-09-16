rule Ransom_MSIL_Cryptolocker_PDL_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 65 20 68 61 76 65 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_2 = {2e 4c 6f 63 6b } 		$a_81_3 = {2e 6f 6e 69 6f 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}