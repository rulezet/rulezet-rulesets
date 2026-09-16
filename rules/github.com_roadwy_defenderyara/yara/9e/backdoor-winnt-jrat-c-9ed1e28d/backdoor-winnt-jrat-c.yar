rule Backdoor_WinNT_Jrat_C{
	meta:
		description = "Backdoor:WinNT/Jrat.C,SIGNATURE_TYPE_JAVAHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {0c 0e 4f 0f 45 09 58 1f 4f 52 4e 1d 5e } 		$a_01_1 = {0e 0f 5e 09 48 1f 45 12 4c 15 4d 52 5e 04 5e } 		$a_01_2 = {0d 41 4c 4c 41 54 4f 52 49 78 44 45 4d 4f } 		$a_01_3 = {2f 62 72 69 64 6a 2f 6a 61 77 74 2f } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}