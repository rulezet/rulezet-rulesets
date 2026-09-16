rule VirTool_Win32_CeeInject_MJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f af c1 0f af c1 0f af c6 6a ?? 99 5f f7 ff 8b 7d ?? 01 45 ?? 8a c1 32 07 3b f3 75 ?? 8a 45 ?? 88 07 } 		$a_03_1 = {03 c1 81 c7 ?? ?? ?? ?? 41 0f af f1 69 f6 ?? ?? ?? ?? 52 ff 75 ?? 89 35 ?? ?? ?? ?? ff 75 ?? ff d0 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}