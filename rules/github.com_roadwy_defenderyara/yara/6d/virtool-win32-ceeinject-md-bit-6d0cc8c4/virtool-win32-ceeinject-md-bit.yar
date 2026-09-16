rule VirTool_Win32_CeeInject_MD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 ac 83 c2 01 89 55 ac 81 7d ac 20 8b 00 00 7d ?? eb } 		$a_01_1 = {8b 45 c4 03 45 ac 8b 4d fc 03 4d ac 8a 11 88 10 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}