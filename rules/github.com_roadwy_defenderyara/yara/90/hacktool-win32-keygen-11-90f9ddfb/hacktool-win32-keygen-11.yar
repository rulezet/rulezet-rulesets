rule HackTool_Win32_Keygen_11{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 64 61 79 61 6e 7a 61 69 2e 6d 65 } 		$a_01_1 = {43 6f 72 65 6c 20 50 72 6f 64 75 63 74 73 20 4b 65 79 67 65 6e } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 41 53 50 72 6f 74 65 63 74 5c 4b 65 79 } 		$a_01_3 = {61 73 70 72 5f 6b 65 79 73 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}