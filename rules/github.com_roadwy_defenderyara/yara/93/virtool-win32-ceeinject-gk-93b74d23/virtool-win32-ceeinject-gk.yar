rule VirTool_Win32_CeeInject_GK{
	meta:
		description = "VirTool:Win32/CeeInject.GK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba ac 3d 60 00 33 c0 f0 0f b1 0a 85 c0 74 } 		$a_01_1 = {55 48 5f 40 8b 06 46 46 89 07 46 46 83 c7 04 49 75 f2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}