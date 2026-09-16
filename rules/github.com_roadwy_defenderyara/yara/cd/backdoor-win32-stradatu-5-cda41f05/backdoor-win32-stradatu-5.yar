rule Backdoor_Win32_Stradatu_5{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 20 50 61 74 68 20 69 73 20 6e 75 6c 6c 21 } 		$a_01_1 = {3c 54 49 54 4c 45 3e 44 69 73 70 6c 61 79 20 49 6e 66 6f 20 66 6f 72 20 74 68 69 73 20 53 49 54 45 21 3c 2f 54 49 54 4c 45 3e } 		$a_01_2 = {63 6f 6e 74 65 6e 74 3d 71 75 69 74 } 		$a_01_3 = {25 61 2c 20 25 64 20 25 62 20 25 59 20 25 48 3a 25 4d 3a 25 53 20 47 4d 54 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}