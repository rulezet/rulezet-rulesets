rule VirTool_Win32_VBInject_AHL_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb fd fa 0f 10 [0-30] 81 c3 13 15 00 00 [0-30] 31 30 [0-30] 83 c0 04 [0-30] 39 58 fc 75 [0-30] 58 [0-30] ff e0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}