rule VirTool_Win32_CeeInject_TO_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 28 f6 d1 30 0c 18 40 3b c6 72 f3 } 		$a_03_1 = {8b ce 2b c8 51 03 c3 50 ff 93 ?? ?? ?? ?? 01 44 24 ?? 59 59 39 74 24 ?? 72 } 		$a_03_2 = {33 c0 81 34 83 ?? ?? ?? ?? 40 83 f8 10 72 f3 } 		$a_03_3 = {50 53 8b c6 e8 ?? ?? ?? ?? 59 59 33 c9 8a 14 0b 8b 44 24 0c 30 14 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}