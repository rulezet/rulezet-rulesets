rule Backdoor_Win32_FlyAgent_H_2{
	meta:
		description = "Backdoor:Win32/FlyAgent.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 41 6e 64 20 44 65 6c 65 74 65 4d 65 2e 62 61 74 } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 46 6c 79 53 6b 79 5c 45 5c 49 6e 73 74 61 6c 6c 5c 50 61 74 68 } 		$a_01_2 = {5c 6d 73 79 69 61 6e 6a 69 75 70 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}