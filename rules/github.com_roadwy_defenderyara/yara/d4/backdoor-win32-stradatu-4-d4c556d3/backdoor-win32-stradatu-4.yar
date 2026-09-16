rule Backdoor_Win32_Stradatu_4{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 78 6a 6d 70 73 76 61 6c 7a 79 64 67 } 		$a_01_1 = {2a 26 75 73 65 72 69 64 3d 2a 2a 2a 2a 26 6f 74 68 65 72 3d } 		$a_01_2 = {70 74 5f 4c 58 43 5f 33 } 		$a_01_3 = {74 65 20 43 6f 6d 6d 61 6e 64 20 53 6f 63 6b 65 74 20 42 75 69 6c 64 20 4f 4b 21 } 		$a_01_4 = {61 74 20 22 49 50 20 50 4f 52 54 22 21 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}