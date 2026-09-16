rule VirTool_Win32_CeeInject_MJ_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.MJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 0a 00 00 00 6a 00 33 c9 58 f7 f1 } 		$a_03_1 = {68 d2 07 00 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 3d 0c 03 00 00 76 } 		$a_01_2 = {b9 a9 6d f1 f3 8b c0 49 75 } 		$a_03_3 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b c8 c1 e1 04 2b c8 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}