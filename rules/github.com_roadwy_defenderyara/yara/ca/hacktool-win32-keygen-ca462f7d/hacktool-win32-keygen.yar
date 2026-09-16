rule HackTool_Win32_Keygen{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {52 61 69 64 65 6e 20 21 20 4c 7a 30 } 		$a_80_1 = {53 45 52 49 41 4c } 		$a_80_2 = {47 65 6e 65 72 61 74 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}