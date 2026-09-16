rule VirTool_Win32_CeeInject_TQ_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 7e 08 89 56 04 c7 46 0c 04 00 00 00 c7 06 00 00 00 00 ff d0 } 		$a_03_1 = {8b 44 24 50 8a 1c 15 ?? ?? ?? ?? 35 ?? ?? ?? ?? 8b 54 24 ?? 8a 3c 0a 8b 74 24 ?? 8b 7c 24 ?? 29 fe 28 df 89 74 24 ?? 8b 74 24 ?? 88 3c 0e 01 c1 } 		$a_03_2 = {eb 00 8b 44 24 ?? 8b 4c 24 ?? 81 c1 ?? ?? ?? ?? 8a 10 89 4c 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 88 14 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}