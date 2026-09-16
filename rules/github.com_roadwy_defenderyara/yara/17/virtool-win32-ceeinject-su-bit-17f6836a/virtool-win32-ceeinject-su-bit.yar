rule VirTool_Win32_CeeInject_SU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4e 08 b8 ?? ?? ?? ?? 8b 1e 2b cb f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 3d } 		$a_03_1 = {8b c1 c1 e8 ?? 30 04 1a 42 3b 55 10 7c 90 09 0c 00 69 c9 ?? ?? ?? ?? 81 c1 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}