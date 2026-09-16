rule VirTool_Win32_CeeInject_TS_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? 99 f7 7d ?? 8b 45 ?? 8a 8a ?? ?? ?? ?? 8b 55 ?? c0 e1 03 32 c8 88 0c 02 40 3b c7 89 45 } 		$a_03_1 = {8b c7 99 f7 7d ?? 8b 45 ?? 8a 04 02 30 04 3e 47 3b 7d ?? 7c eb } 		$a_03_2 = {8b c1 99 bf ?? ?? 00 00 f7 ff 8b 45 ?? 8a 04 02 30 04 31 41 81 f9 1d 02 00 00 7c e4 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}