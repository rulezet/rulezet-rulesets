rule Ransom_Win32_Cryptolocker_PDR_MTB_2{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {66 75 63 6b 79 6f 75 } 		$a_81_1 = {44 65 63 72 79 70 74 2d 6d 65 } 		$a_81_2 = {72 65 63 6f 76 65 72 66 69 6c 65 73 } 		$a_81_3 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } 		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}