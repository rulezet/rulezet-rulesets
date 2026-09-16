rule VirTool_Win32_CeeInject_MZ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 4d ff 30 0c 30 40 3b 07 7c f5 } 		$a_03_1 = {e8 b9 86 00 00 99 b9 17 00 00 00 f7 f9 8d b5 ?? ?? ?? ?? 8d 5a 61 e8 ?? ?? ?? ?? 4f 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}