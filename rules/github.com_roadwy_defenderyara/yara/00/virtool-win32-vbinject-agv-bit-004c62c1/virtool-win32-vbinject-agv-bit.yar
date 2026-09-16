rule VirTool_Win32_VBInject_AGV_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 1c [0-20] 0f ef d9 [0-20] 0f 7e d8 [0-20] 83 f8 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}