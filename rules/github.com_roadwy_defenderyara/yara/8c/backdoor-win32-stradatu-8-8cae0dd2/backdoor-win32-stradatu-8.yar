rule Backdoor_Win32_Stradatu_8{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 20 71 75 69 74 21 5b 61 6c 6c 20 73 6c 65 65 70 20 6e 6e 6e 20 74 69 6d 65 5d } 		$a_01_1 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 4e 65 77 20 63 6c 69 65 6e 74 20 63 6f 6d 69 6e 67 20 21 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a } 		$a_01_2 = {42 61 64 20 43 6c 69 65 6e 74 2c 20 70 6c 65 61 73 65 20 72 65 6d 6f 76 65 20 69 74 21 } 		$a_01_3 = {25 73 20 67 6f 65 73 20 74 6f 20 62 65 64 21 20 57 69 73 68 20 68 69 6d 20 61 20 67 6f 6f 64 20 73 6c 65 65 70 21 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}