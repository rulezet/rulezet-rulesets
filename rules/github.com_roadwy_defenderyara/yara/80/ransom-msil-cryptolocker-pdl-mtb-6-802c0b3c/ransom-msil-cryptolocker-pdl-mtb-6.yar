rule Ransom_MSIL_Cryptolocker_PDL_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 61 72 65 20 66 6f 72 6d 61 74 74 65 64 } 		$a_81_1 = {48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 } 		$a_81_2 = {72 61 6e 73 6f 6d 2e 6a 70 67 } 		$a_81_3 = {2e 43 72 79 70 74 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}