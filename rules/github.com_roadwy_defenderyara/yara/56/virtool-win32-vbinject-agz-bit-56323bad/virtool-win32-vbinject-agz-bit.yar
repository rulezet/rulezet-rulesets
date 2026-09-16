rule VirTool_Win32_VBInject_AGZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 96 39 14 00 [0-10] 05 c0 c6 2d 00 [0-10] 39 41 04 75 [0-10] 68 cd 7b 34 00 [0-10] 58 [0-10] 05 80 84 1e 00 [0-10] 39 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}