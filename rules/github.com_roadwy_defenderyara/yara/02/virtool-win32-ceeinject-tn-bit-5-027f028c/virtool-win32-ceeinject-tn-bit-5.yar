rule VirTool_Win32_CeeInject_TN_bit_5{
	meta:
		description = "VirTool:Win32/CeeInject.TN!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c8 31 d2 8b 74 24 ?? f7 f6 8b 7c 24 ?? 8a 1c 15 ?? ?? ?? ?? 89 7c 24 ?? 8b 54 24 ?? 8a 3c 0a 28 df 8b 7c 24 ?? 88 3c 0f } 		$a_03_1 = {89 c1 83 e1 07 8a 14 05 ?? ?? ?? ?? 2a 14 0d ?? ?? ?? ?? 88 54 04 ?? 83 c0 01 89 44 24 ?? 83 f8 0e 0f 84 } 		$a_03_2 = {31 c0 8b 4c 24 ?? 8b 51 3c 01 d1 8b 74 24 ?? 8b 14 16 81 fa 50 45 00 00 0f 44 c1 89 c1 83 c1 06 66 83 78 06 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}