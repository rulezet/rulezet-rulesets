rule Backdoor_Win32_Stradatu{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 46 4e 3d 25 73 26 4c 46 4c 3d 25 6c 64 26 52 46 4e 3d 25 73 } 		$a_01_1 = {66 72 69 65 6e 64 20 69 73 20 55 6e 61 76 61 69 6c 61 62 6c 65 21 } 		$a_01_2 = {3a 5c 70 6a 74 73 32 30 30 38 5c 53 75 6e 54 61 6c 6b 5c 52 65 6c 65 61 73 65 5c 53 54 61 6c 6b 5f 53 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}