rule Backdoor_Win32_Zegost{
	meta:
		description = "Backdoor:Win32/Zegost,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6c 58 25 69 6b 5c 6c 61 62 6f 6c 47 73 25 73 25 } 		$a_01_1 = {6b 2d 20 65 78 65 2e 74 73 6f 68 } 		$a_01_2 = {2e 33 33 32 32 2e 6f 72 67 } 		$a_01_3 = {25 73 6f 74 25 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 25 73 20 25 73 25 73 25 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}