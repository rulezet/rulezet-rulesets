rule Ransom_MSIL_Cryptolocker_PDL_MTB_8{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } 		$a_81_1 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } 		$a_81_2 = {2f 43 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } 		$a_81_3 = {52 45 41 44 5f 4d 45 5f 46 49 4c 45 5f 45 4e 43 52 59 50 54 45 44 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}