rule Backdoor_WinNT_Jrat_C_4{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {14 4c 66 75 7a 7a 6c 65 2f 42 43 4a 49 6e 6a 65 63 74 6f 72 3b } 		$a_01_1 = {11 4c 63 6f 6e 66 69 67 2f 52 65 67 69 73 74 72 79 3b } 		$a_01_2 = {13 4c 63 6f 6e 66 69 67 2f 42 79 74 65 4c 6f 61 64 65 72 3b } 		$a_01_3 = {0d 63 6f 6e 66 69 67 2f 52 65 61 64 49 4f } 		$a_01_4 = {07 5d 15 44 18 45 0b 59 } 		$a_01_5 = {06 14 43 18 4e 19 44 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}