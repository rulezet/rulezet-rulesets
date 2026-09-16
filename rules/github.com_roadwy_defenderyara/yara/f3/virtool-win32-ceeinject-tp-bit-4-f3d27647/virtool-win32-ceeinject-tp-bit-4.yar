rule VirTool_Win32_CeeInject_TP_bit_4{
	meta:
		description = "VirTool:Win32/CeeInject.TP!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 11 8b 0c 24 81 c1 33 f9 03 59 89 4c 24 ?? 8b 4c 24 ?? 88 14 01 } 		$a_03_1 = {89 54 24 7c 8b 96 ?? ?? ?? ?? 8b 9c 24 ?? 00 00 00 8b b6 ?? ?? ?? ?? 31 fe 81 f3 ?? ?? ?? ?? 8b 7c 24 ?? 01 c7 } 		$a_03_2 = {89 c8 31 d2 8b 74 24 ?? f7 f6 8b 7c 24 ?? 8a 1c 0f 2a 1c 15 ?? ?? ?? ?? 8b 54 24 ?? 88 1c 0a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}