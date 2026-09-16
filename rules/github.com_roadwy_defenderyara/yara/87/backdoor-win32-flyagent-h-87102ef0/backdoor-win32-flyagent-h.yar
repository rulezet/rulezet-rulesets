rule Backdoor_Win32_FlyAgent_H{
	meta:
		description = "Backdoor:Win32/FlyAgent.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 41 6e 64 20 78 4d 65 2e 62 61 74 } 		$a_01_1 = {53 6b 79 5c 45 5c 49 6e 73 74 61 6c 6c 5c 50 61 74 68 } 		$a_01_2 = {6f 6e 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}