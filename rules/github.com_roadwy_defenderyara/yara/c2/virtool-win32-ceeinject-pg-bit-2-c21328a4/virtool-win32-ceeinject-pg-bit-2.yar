rule VirTool_Win32_CeeInject_PG_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.PG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b fa c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 16 33 c7 2b c8 8b c1 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 0e 2b 75 f8 33 c7 2b d0 ff 4d fc 75 } 		$a_03_1 = {56 57 be 20 37 ef c6 e8 ?? ?? ?? ?? 89 45 f8 c7 45 fc 20 00 00 00 } 		$a_03_2 = {ff 15 0c c0 ?? 01 8a 86 ?? ?? ?? ?? 88 04 1e ff 15 08 c0 ?? 01 83 fe 0a 75 20 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}