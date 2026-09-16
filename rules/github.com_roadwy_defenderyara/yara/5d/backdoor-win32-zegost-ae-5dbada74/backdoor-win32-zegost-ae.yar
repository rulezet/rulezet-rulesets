rule Backdoor_Win32_Zegost_AE{
	meta:
		description = "Backdoor:Win32/Zegost.AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 c6 45 ed 68 c6 45 ee 30 c6 45 ef 73 } 		$a_01_1 = {48 c6 44 24 11 61 c6 44 24 12 63 c6 44 24 13 6b c6 44 24 14 65 c6 44 24 15 72 c6 44 24 16 3a } 		$a_02_2 = {5c 73 79 73 6c 6f 67 2e 64 61 74 [0-10] 25 64 2e 62 61 6b } 		$a_01_3 = {47 6c 6f 62 61 6c 5c 55 55 50 50 20 25 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}