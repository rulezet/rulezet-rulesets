rule VirTool_Win32_VBInject_AGU_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 0c [0-20] 0f ef d9 [0-20] 0f 7e d9 [0-20] 81 f9 00 00 04 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}