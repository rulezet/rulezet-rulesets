rule VirTool_Win32_VBInject_AHE_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHE!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 56 f7 04 00 [0-20] 58 [0-20] 05 00 09 3d 00 [0-20] 39 41 04 [0-20] 68 cd 7b 34 00 [0-20] 58 [0-20] 05 80 84 1e 00 [0-20] 39 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}