rule HackTool_Win64_Dumplsass_B_2{
	meta:
		description = "HackTool:Win64/Dumplsass.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 69 74 63 65 6a 6e 49 79 42 70 6d 75 44 7a 74 6b 4d } 		$a_01_1 = {64 72 6f 77 73 73 61 50 70 6d 75 44 63 6f 72 50 79 42 70 6d 75 44 7a 74 6b 4d } 		$a_01_2 = {43 44 79 42 70 6d 75 44 7a 74 6b 4d } 		$a_01_3 = {65 6c 69 46 6d 61 53 79 42 70 6d 75 44 7a 74 6b 4d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}