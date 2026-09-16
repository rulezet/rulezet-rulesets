rule Backdoor_Win32_Tibs{
	meta:
		description = "Backdoor:Win32/Tibs,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 69 62 73 3a 2f 2f 63 6f 6e 6e 65 63 74 } 		$a_01_1 = {4f 6c 65 61 63 63 2e 64 6c 6c } 		$a_01_2 = {54 65 73 74 20 44 6f 77 6e 6c 6f 61 64 } 		$a_01_3 = {68 74 74 70 3a 2f 2f 64 69 72 65 63 74 70 6c 75 67 69 6e 2e 63 6f 6d 2f 64 69 61 6c 65 72 73 2f } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}