rule VirTool_Win32_CeeInject_gen_HL{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 04 24 ff d5 83 ec 28 85 c0 0f 84 ?? ?? 00 00 c7 44 24 0c 04 00 00 00 c7 44 24 08 00 10 00 00 c7 44 24 04 04 00 00 00 c7 04 24 00 00 00 00 ff 54 24 ?? 83 ec 10 a3 ?? ?? ?? ?? c7 00 07 00 01 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}