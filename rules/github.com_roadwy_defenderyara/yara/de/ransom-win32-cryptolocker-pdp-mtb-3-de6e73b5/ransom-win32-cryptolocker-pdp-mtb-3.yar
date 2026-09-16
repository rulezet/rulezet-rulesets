rule Ransom_Win32_Cryptolocker_PDP_MTB_3{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {46 49 4c 45 53 20 45 4e 43 52 59 50 54 45 44 } 		$a_81_1 = {54 6f 75 63 68 4d 65 4e 6f 74 } 		$a_81_2 = {52 45 43 59 43 4c 45 52 5c 5f 5f 65 6d 70 74 79 } 		$a_81_3 = {53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c 5f 5f 65 6d 70 74 79 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}