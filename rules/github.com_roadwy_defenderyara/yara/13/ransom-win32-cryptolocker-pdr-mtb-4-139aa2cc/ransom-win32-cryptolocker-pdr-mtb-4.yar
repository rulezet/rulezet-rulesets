rule Ransom_Win32_Cryptolocker_PDR_MTB_4{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {41 45 53 2d 32 35 36 20 4d 49 4c 4c 49 54 41 52 59 } 		$a_81_2 = {52 45 53 54 4f 52 45 20 47 45 54 20 42 41 43 4b 20 59 4f 55 52 20 46 49 4c 45 53 } 		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}