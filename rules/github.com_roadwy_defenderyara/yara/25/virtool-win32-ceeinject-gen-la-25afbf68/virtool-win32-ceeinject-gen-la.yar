rule VirTool_Win32_CeeInject_gen_LA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 06 50 c6 46 01 24 c6 46 02 78 90 13 e8 00 00 00 00 58 89 45 fc } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}