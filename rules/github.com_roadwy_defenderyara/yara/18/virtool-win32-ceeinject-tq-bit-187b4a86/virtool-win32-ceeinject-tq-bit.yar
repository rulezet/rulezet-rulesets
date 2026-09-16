rule VirTool_Win32_CeeInject_TQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 43 01 be ?? ?? ?? ?? 33 d2 f7 f6 8b c1 03 c3 88 10 43 81 fb ?? ?? ?? ?? 75 } 		$a_03_1 = {03 c3 8a 00 [0-10] 34 dc 8b 15 ?? ?? ?? ?? 03 d3 88 02 [0-10] 43 81 fb ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}