rule VirTool_Win32_CeeInject_TN_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 8b 75 ?? 88 14 06 8b 7d ?? 81 f7 ?? ?? ?? ?? 89 7d ?? 83 c0 01 8b 7d ?? 39 f8 89 45 90 09 06 00 8b 45 ?? 8b 4d } 		$a_03_1 = {89 c8 31 d2 8b 74 24 ?? f7 f6 8b 7c 24 ?? 8a 1c 0f 2a 1c 15 ?? ?? ?? ?? 8b 54 24 ?? 88 1c 0a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}