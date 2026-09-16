rule VirTool_Win32_VBInject_OS_bit{
	meta:
		description = "VirTool:Win32/VBInject.OS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 8b 0d 18 00 00 00 [0-40] 8b 49 30 [0-40] 02 51 02 [0-40] ff e2 } 		$a_03_1 = {8b 43 2c eb [0-40] 0f 6e e0 [0-40] 0f ef e6 [0-40] 0f 7e e0 [0-40] 83 f8 00 0f 85 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}