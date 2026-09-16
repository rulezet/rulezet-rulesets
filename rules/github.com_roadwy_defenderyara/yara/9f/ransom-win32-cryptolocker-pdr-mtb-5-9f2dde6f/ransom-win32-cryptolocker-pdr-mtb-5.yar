rule Ransom_Win32_Cryptolocker_PDR_MTB_5{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } 		$a_81_1 = {42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 } 		$a_81_2 = {42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 } 		$a_81_3 = {42 41 53 45 36 34 45 4e 43 52 59 50 54 45 44 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}