rule VirTool_Win32_CeeInject_OA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 02 8b 44 24 ?? 09 c0 8b 54 24 ?? 09 d2 8b 74 24 ?? 89 54 24 ?? 89 44 24 ?? 8b 44 24 ?? 88 1c 06 81 e1 ?? ?? ?? ?? 89 4c 24 ?? eb } 		$a_03_1 = {89 e1 8b 54 24 ?? 89 51 0c 8b 74 24 ?? 89 71 04 89 01 c7 41 08 ?? ?? ?? ?? 8b 44 24 ?? ff d0 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}