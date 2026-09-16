rule Backdoor_Win32_Stradatu_6{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 20 71 75 69 74 21 5b 61 6c 6c 20 73 6c 65 65 70 20 6e 6e 6e 20 74 69 6d 65 5d } 		$a_01_1 = {3c 4e 55 4c 4c 3e 20 50 61 73 73 77 6f 72 64 3c 4e 55 4c 4c 3e 20 44 6f 6d 61 69 6e 3c 4e 55 4c 4c 3e } 		$a_01_2 = {2a 2a 2a 20 4a 4d 53 2d 48 54 20 2a 2a 2a } 		$a_01_3 = {6c 20 69 6e 20 61 6e 6f 74 68 65 72 20 73 68 65 6c 6c 21 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}