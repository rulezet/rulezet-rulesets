rule HackTool_Win32_Keygen_10{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e 20 62 79 20 50 41 52 41 44 4f 58 } 		$a_01_1 = {53 74 6f 70 2f 50 6c 61 79 20 4d 75 73 69 63 } 		$a_01_2 = {47 65 6e 65 72 61 74 65 20 43 44 2d 4b 65 79 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}