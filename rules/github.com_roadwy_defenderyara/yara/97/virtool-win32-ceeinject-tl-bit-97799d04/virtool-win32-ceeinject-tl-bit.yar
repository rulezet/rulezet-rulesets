rule VirTool_Win32_CeeInject_TL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 d2 75 09 8b 45 ?? 83 c0 03 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 8a 82 ?? ?? ?? 00 88 01 eb b6 } 		$a_03_1 = {00 00 73 13 8b 55 ?? 03 55 ?? 8b 45 ?? 8a 88 ?? ?? ?? 00 88 0a eb db } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}