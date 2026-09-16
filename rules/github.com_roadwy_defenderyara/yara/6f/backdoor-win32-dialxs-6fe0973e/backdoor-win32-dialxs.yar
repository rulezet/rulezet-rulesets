rule Backdoor_Win32_DialXS{
	meta:
		description = "Backdoor:Win32/DialXS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 6e 6c 2f } 		$a_01_1 = {28 43 29 44 69 61 6c 58 53 } 		$a_01_2 = {4c 69 63 65 6e 73 65 20 76 6f 69 6c 61 74 65 64 } 		$a_01_3 = {52 61 73 53 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } 		$a_01_4 = {50 72 6f 78 79 45 6e 61 62 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}