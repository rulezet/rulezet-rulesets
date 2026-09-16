rule Backdoor_Win32_Zegost_AE_2{
	meta:
		description = "Backdoor:Win32/Zegost.AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 c6 45 ed 68 c6 45 ee 30 c6 45 ef 73 } 		$a_01_1 = {5c 73 79 73 74 65 6d 69 6e 66 6f 2e 6b 65 79 00 25 32 64 25 32 64 } 		$a_01_2 = {61 50 50 4c 49 43 41 54 49 4f 4e 53 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 5c 53 48 45 4c 4c 5c 4f 50 45 4e 5c 43 4f 4d 4d 41 4e 44 00 } 		$a_01_3 = {54 65 72 6d 69 6e 61 74 65 54 68 72 65 61 64 00 25 73 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}