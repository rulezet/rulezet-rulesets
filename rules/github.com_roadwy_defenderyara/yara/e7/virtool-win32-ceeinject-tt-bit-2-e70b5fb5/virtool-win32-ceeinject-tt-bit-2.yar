rule VirTool_Win32_CeeInject_TT_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 ff 0f b6 9a ?? ?? ?? ?? c1 e3 1b 8b d1 c1 e2 18 33 da c1 eb 18 88 1c 31 41 81 f9 ?? ?? ?? ?? 72 } 		$a_01_1 = {f7 e9 8b d9 c1 fb 1f 03 d1 c1 fa 09 2b d3 69 d2 ef 02 00 00 f7 da 03 d1 0f b6 1c 32 30 1f 47 41 } 		$a_03_2 = {f7 e9 8b f1 c1 fe 1f c1 fa 08 2b d6 69 d2 9a 04 00 00 47 f7 da 8b 74 24 ?? 03 d1 0f b6 14 32 41 30 13 43 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}