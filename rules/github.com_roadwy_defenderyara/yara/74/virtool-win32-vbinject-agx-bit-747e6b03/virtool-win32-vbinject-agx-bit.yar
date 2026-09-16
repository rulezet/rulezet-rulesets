rule VirTool_Win32_VBInject_AGX_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGX!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 16 dc 2d 00 [0-20] 58 [0-20] 05 40 24 14 00 [0-20] 39 41 04 [0-20] 68 8d a3 3d 00 [0-20] 58 [0-20] 05 c0 5c 15 00 [0-20] 39 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}