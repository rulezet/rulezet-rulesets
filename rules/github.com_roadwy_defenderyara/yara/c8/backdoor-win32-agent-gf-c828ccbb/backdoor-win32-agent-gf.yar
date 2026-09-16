rule Backdoor_Win32_Agent_GF{
	meta:
		description = "Backdoor:Win32/Agent.GF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 33 36 30 } 		$a_01_1 = {66 75 63 6b 77 65 62 } 		$a_01_2 = {00 64 6c 6c 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}