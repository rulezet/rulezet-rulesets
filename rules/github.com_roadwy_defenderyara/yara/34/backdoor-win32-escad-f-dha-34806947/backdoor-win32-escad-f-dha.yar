rule Backdoor_Win32_Escad_F_dha{
	meta:
		description = "Backdoor:Win32/Escad.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 72 65 67 6b 5d 00 00 5b 77 6f 77 36 34 5d 00 5b 6e 74 66 73 5d 00 00 5b 64 69 72 61 5d 00 00 5b 64 69 72 72 5d 00 } 		$a_01_1 = {77 65 76 74 75 74 69 6c 2e 65 78 65 20 63 6c 20 22 25 73 22 20 2f 62 75 3a 22 25 73 22 00 } 		$a_01_2 = {25 73 5c 66 78 25 69 25 69 2e 62 61 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}