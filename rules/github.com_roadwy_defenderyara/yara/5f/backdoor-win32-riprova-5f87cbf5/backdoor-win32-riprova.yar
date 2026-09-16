rule Backdoor_Win32_Riprova{
	meta:
		description = "Backdoor:Win32/Riprova,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 69 70 72 6f 76 61 2e 2e 2e 00 25 64 00 } 		$a_01_1 = {43 3a 5c 5c 73 67 72 75 6e 74 } 		$a_01_2 = {64 69 73 69 6e 73 74 61 6c 6c 61 2e 68 74 6d } 		$a_01_3 = {49 45 34 33 32 31 2e 65 78 65 } 		$a_01_4 = {77 77 77 2e 73 67 72 75 6e 74 2e 62 69 7a 2f } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*4) >=13
 
}