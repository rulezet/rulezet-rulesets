rule HackTool_Win32_Keygen_MTB_8{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e } 		$a_01_1 = {6b 65 79 73 68 6f 74 } 		$a_01_2 = {4b 65 79 4d 65 73 68 69 6e 67 } 		$a_01_3 = {4c 75 78 69 6f 6e 20 4b 65 79 73 68 6f 74 } 		$a_01_4 = {72 61 6e 64 6f 6d 20 6e 75 6d 62 65 72 20 67 65 6e 65 72 61 74 6f 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}