rule VirTool_Win32_CeeInject_RT_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.RT!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 8b 01 8b 40 0c 8b 40 0c 8b 00 } 		$a_01_1 = {8b 00 8b 40 18 89 45 f8 } 		$a_01_2 = {68 4d 12 1f 52 57 89 46 58 } 		$a_03_3 = {50 c7 45 e4 ?? ?? ?? ?? c7 45 e8 ?? ?? ?? ?? ff 56 48 89 45 fc } 		$a_03_4 = {8b c1 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 c6 ?? ?? ff 06 81 3e ?? ?? ?? ?? 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*5) >=9
 
}