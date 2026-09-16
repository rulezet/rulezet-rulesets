rule Backdoor_Win32_Wolyx_B{
	meta:
		description = "Backdoor:Win32/Wolyx.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 79 6f 75 00 } 		$a_01_1 = {6d 73 73 65 63 65 73 00 ff ff ff ff 0a 00 00 00 73 70 69 64 65 72 67 61 74 65 00 00 ff ff ff ff 08 00 00 00 75 66 73 65 61 67 6e 74 00 } 		$a_01_2 = {49 45 69 6e 66 6f 2e 64 6c 6c 00 57 53 50 53 74 61 72 74 75 70 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}