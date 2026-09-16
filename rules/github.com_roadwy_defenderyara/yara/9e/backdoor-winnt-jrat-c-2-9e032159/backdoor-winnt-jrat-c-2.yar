rule Backdoor_WinNT_Jrat_C_2{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {05 37 37 24 4e 5a } 		$a_01_1 = {0d 11 07 10 0d 16 10 c0 80 07 4d 06 02 16 } 		$a_01_2 = {0a 64 65 63 6f 6d 70 72 65 73 73 } 		$a_01_3 = {11 63 6f 6e 66 69 67 2f 42 79 74 65 4c 6f 61 64 65 72 } 		$a_01_4 = {84 03 ff 1c 82 92 55 1d 9b 00 16 2b 2a 1d 84 03 ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5) >=9
 
}