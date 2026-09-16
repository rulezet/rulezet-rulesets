rule Backdoor_Win32_Oratof_SK_MTB{
	meta:
		description = "Backdoor:Win32/Oratof.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 35 74 67 65 72 61 70 75 } 		$a_01_1 = {77 67 71 68 71 62 6d 69 6b 6c 77 64 6f 61 67 69 71 } 		$a_01_2 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } 		$a_01_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}