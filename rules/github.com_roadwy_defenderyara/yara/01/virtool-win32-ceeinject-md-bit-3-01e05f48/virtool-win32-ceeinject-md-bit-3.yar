rule VirTool_Win32_CeeInject_MD_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.MD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 d2 fd 43 03 00 81 c2 ?? ?? ?? ?? 8b c2 c1 e8 10 32 04 0b 46 88 01 8b 7d ?? 41 3b f7 7c } 		$a_03_1 = {51 6a 40 57 50 6a 00 ff 15 ?? ?? ?? ?? ff 55 f4 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}