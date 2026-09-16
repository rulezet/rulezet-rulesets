rule VirTool_Win32_CeeInject_TT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 04 39 49 75 fa } 		$a_03_1 = {6a 00 89 0c ?? 33 c9 03 c8 8b f9 59 6a 00 89 04 ?? 33 c0 03 c7 89 83 ?? ?? ?? ?? 58 6a 00 89 04 ?? 2b c0 0b 83 ?? ?? ?? ?? 8b f0 58 6a 00 89 3c ?? 33 ff 0b bb ?? ?? ?? ?? 8b cf 5f f3 a4 } 		$a_01_2 = {52 59 03 cb 8b d1 59 23 d9 55 8b e8 33 eb 8b c5 5d ff e0 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}