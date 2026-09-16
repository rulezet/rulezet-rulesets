rule VirTool_Win32_CeeInject_TS_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TS!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 24 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 0f b6 0c 10 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01 } 		$a_03_1 = {73 15 8b 4d ?? c1 e1 03 8b 55 ?? d3 ea 8b 45 ?? 03 45 ?? 88 10 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}