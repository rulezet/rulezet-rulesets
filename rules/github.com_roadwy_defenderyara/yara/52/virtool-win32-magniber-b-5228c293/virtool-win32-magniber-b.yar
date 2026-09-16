rule VirTool_Win32_Magniber_B{
	meta:
		description = "VirTool:Win32/Magniber.B,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } 		$a_00_1 = {20 00 2f 00 63 00 20 00 } 		$a_00_2 = {20 00 26 00 26 00 20 00 } 		$a_00_3 = {25 00 20 00 7c 00 20 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}