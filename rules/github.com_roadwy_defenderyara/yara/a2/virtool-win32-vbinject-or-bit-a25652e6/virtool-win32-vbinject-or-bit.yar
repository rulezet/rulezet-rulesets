rule VirTool_Win32_VBInject_OR_bit{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 [0-30] 41 [0-30] 8b 53 2c [0-30] 31 ca [0-30] 83 fa 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}