rule VirTool_Win32_CeeInject_TO_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db } 		$a_03_1 = {8b d0 83 e2 0f 8a 92 ?? ?? ?? ?? 33 db 8a d9 88 14 1e c1 e8 04 49 85 c0 75 e6 } 		$a_03_2 = {30 1a eb 05 ?? ?? ?? ?? ?? 42 eb 05 ?? ?? ?? ?? ?? 49 eb 05 ?? ?? ?? ?? ?? 83 f9 00 eb 05 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}