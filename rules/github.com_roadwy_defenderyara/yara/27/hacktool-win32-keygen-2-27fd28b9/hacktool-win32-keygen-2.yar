rule HackTool_Win32_Keygen_2{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {43 6f 64 65 20 61 6e 64 20 4b 65 79 67 65 6e } 		$a_80_1 = {63 72 69 6d 69 6e 61 6c 6c 79 20 69 6e 73 61 6e 65 } 		$a_80_2 = {47 46 58 3a 20 6b 52 38 56 69 54 79 2f 43 52 4f } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}