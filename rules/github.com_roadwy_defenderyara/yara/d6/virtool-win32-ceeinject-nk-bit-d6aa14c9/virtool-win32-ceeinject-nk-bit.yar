rule VirTool_Win32_CeeInject_NK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 45 fc 0f b6 00 3d cc 00 00 00 74 0d 8b 45 fc 0f b6 00 3d 90 00 00 00 75 06 } 		$a_03_1 = {89 4d 94 81 7d 94 31 33 24 72 74 1d [0-30] ff 55 a4 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}