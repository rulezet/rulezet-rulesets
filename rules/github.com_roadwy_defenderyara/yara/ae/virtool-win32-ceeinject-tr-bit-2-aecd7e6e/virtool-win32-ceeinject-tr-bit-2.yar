rule VirTool_Win32_CeeInject_TR_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 72 0c 89 4a 04 c7 42 08 00 10 00 00 c7 02 00 00 00 00 ff d0 } 		$a_03_1 = {74 d9 8b 44 24 ?? 8b 4c 24 ?? 83 f1 ?? 8b 54 24 ?? 8a 1c 02 89 4c 24 ?? 8b 4c 24 ?? 88 1c 01 83 c0 01 89 44 24 ?? 8b 74 24 ?? 39 f0 } 		$a_03_2 = {89 fa f7 f1 8b 4c 24 ?? 8b 7c 24 ?? 89 7c 24 ?? 8b 7c 24 ?? 29 cf 8a 1c 15 ?? ?? ?? ?? 8b 4c 24 ?? 8a 3c 31 28 df 8b 54 24 ?? 88 3c 32 01 fe } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}