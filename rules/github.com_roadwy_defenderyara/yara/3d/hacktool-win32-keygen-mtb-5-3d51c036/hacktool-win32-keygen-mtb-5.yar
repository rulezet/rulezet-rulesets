rule HackTool_Win32_Keygen_MTB_5{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 65 73 73 20 67 65 6e 65 72 61 74 65 20 6f 72 20 70 61 73 74 65 20 73 65 72 69 61 6c } 		$a_01_1 = {50 61 73 74 65 20 72 65 71 75 65 73 74 20 63 6f 64 65 20 68 65 72 65 } 		$a_01_2 = {49 6e 76 61 6c 69 64 20 72 65 71 75 65 73 74 20 63 6f 64 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}