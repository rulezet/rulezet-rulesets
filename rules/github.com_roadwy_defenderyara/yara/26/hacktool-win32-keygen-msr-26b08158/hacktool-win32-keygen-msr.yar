rule HackTool_Win32_Keygen_MSR{
	meta:
		description = "HackTool:Win32/Keygen!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 61 73 65 55 53 5f 44 52 57 2e 65 78 65 } 		$a_80_1 = {41 63 74 69 76 61 74 65 64 } 		$a_80_2 = {72 6f 6f 74 5c 43 49 4d 56 32 } 		$a_80_3 = {6f 72 70 68 61 6e 20 70 61 63 6b 61 67 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}