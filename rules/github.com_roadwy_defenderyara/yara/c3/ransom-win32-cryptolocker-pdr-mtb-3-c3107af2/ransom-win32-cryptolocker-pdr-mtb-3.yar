rule Ransom_Win32_Cryptolocker_PDR_MTB_3{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {54 6f 75 63 68 4d 65 4e 6f 74 } 		$a_81_2 = {2e 43 72 59 70 54 65 44 } 		$a_81_3 = {64 65 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}