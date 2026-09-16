rule VirTool_Win32_SuspClickFix_M{
	meta:
		description = "VirTool:Win32/SuspClickFix.M,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 } 		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } 		$a_00_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 } 		$a_00_3 = {6d 00 73 00 68 00 74 00 61 00 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=6
 
}