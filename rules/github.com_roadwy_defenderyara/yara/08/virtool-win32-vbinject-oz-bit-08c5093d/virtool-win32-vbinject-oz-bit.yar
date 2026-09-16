rule VirTool_Win32_VBInject_OZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.OZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 [0-20] 8b 40 0c [0-20] 8b 40 14 [0-20] 8b 00 [0-20] 8b 58 28 [0-20] 81 3b 4d 00 53 00 75 [0-20] 81 7b 04 56 00 42 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}