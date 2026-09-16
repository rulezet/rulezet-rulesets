rule HackTool_Win32_Keygen_MTB{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 61 20 5b 46 41 4c 4c 45 4e 5d } 		$a_01_1 = {52 65 67 69 73 74 72 61 74 69 6f 6e 20 43 6f 64 65 20 3a } 		$a_01_2 = {47 26 65 6e 65 72 61 74 65 } 		$a_01_3 = {6b 65 79 6d 61 6b 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}