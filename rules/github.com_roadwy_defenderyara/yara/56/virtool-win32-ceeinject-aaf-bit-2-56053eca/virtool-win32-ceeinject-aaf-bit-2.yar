rule VirTool_Win32_CeeInject_AAF_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.AAF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 04 c1 ea 05 03 54 24 08 33 c2 33 c1 c3 } 		$a_03_1 = {51 55 8b d0 8b cb e8 ?? ?? ?? ?? 2b f8 59 59 8b cf 8b c7 c1 e9 05 03 4c 24 ?? c1 e0 04 03 44 24 ?? 33 c8 8d 04 2f 33 c8 8b 44 24 ?? 2b d9 6a f7 59 2b c8 8b 44 24 ?? 03 e9 8b 4c 24 } 		$a_03_2 = {03 c0 50 57 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}