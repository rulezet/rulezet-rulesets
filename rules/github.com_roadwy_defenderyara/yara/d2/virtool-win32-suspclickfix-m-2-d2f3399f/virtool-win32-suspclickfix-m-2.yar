rule VirTool_Win32_SuspClickFix_M_2{
	meta:
		description = "VirTool:Win32/SuspClickFix.M,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 } 		$a_00_1 = {72 00 6f 00 6f 00 74 00 40 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}