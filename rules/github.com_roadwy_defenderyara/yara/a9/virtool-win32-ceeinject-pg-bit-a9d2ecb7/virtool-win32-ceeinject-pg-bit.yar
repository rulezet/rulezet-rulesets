rule VirTool_Win32_CeeInject_PG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.PG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 8b 01 66 3d 4d 5a 75 f1 8b 59 3c 03 d9 66 8b 03 66 3d 50 45 75 e3 } 		$a_01_1 = {c7 00 56 69 72 74 c7 40 04 75 61 6c 41 c7 40 08 6c 6c 6f 63 } 		$a_03_2 = {03 d8 83 c3 ?? 0f b7 40 ?? 8b d0 c1 e2 ?? 8d 14 92 03 da 83 c3 ?? 8b 4b ?? 03 4d ?? 83 c1 ?? 8b 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}