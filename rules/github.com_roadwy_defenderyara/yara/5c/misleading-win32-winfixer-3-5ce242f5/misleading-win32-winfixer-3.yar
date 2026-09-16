rule Misleading_Win32_Winfixer_3{
	meta:
		description = "Misleading:Win32/Winfixer,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 73 2e 77 69 6e 73 6f 66 74 77 61 72 65 2e 63 6f 6d 2f } 		$a_01_1 = {65 72 72 2e 6c 6f 67 } 		$a_01_2 = {26 70 63 69 64 3d } 		$a_01_3 = {2f 70 69 6e 67 2e 70 68 70 } 		$a_01_4 = {75 70 2e 64 61 74 } 		$a_01_5 = {64 65 6c 64 2e 62 61 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}