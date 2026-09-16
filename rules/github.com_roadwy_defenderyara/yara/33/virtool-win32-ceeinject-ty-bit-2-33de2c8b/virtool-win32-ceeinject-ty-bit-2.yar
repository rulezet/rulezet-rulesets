rule VirTool_Win32_CeeInject_TY_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8b 4d 18 03 4d f0 0f b6 09 33 8c 85 ?? ?? ?? ff 8b 45 18 03 45 f0 88 08 } 		$a_03_1 = {8b 4d 08 03 48 10 89 4d ?? e8 ?? ?? ?? 00 6a 00 ff 75 0c ff 75 08 ff 55 ?? 89 45 ?? e8 ?? ?? ?? 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}