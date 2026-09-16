rule VirTool_Win32_CeeInject_gen_DZ_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 46 28 03 46 34 } 		$a_01_1 = {ff 76 50 ff 76 34 } 		$a_03_2 = {07 00 01 00 (90 09 0b 00 c7 84 24|90 09 0a 00 c7 85) } 		$a_03_3 = {07 00 01 00 90 09 03 00 c7 45 } 		$a_01_4 = {56 65 72 79 50 44 46 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*-10) >=5
 
}