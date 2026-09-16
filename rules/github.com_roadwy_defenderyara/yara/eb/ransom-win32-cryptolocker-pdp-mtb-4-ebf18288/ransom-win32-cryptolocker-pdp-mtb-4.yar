rule Ransom_Win32_Cryptolocker_PDP_MTB_4{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 51 75 69 65 74 } 		$a_81_1 = {45 4e 43 52 59 50 54 45 44 5f 45 58 54 45 4e 54 49 4f 4e } 		$a_81_2 = {45 4e 43 52 59 50 54 5f 4b 45 59 } 		$a_81_3 = {44 45 43 52 59 50 54 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}