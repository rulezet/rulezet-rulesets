rule VirTool_Win32_ExcludeProc_D{
	meta:
		description = "VirTool:Win32/ExcludeProc.D,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 } 		$a_02_1 = {20 00 2d 00 45 00 6e 00 63 00 [0-20] 20 00 50 00 41 00 41 00 6a 00 41 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}