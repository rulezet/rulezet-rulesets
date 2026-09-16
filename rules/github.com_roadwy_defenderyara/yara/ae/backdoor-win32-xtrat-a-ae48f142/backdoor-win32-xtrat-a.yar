rule Backdoor_Win32_Xtrat_A{
	meta:
		description = "Backdoor:Win32/Xtrat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 00 54 00 52 00 45 00 4d 00 45 00 } 		$a_01_1 = {55 6e 69 74 49 6e 6a 65 63 74 53 65 72 76 65 72 } 		$a_01_2 = {54 55 6e 69 74 49 6e 66 65 63 74 55 53 42 } 		$a_01_3 = {54 53 65 72 76 65 72 4b 65 79 6c 6f 67 67 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}