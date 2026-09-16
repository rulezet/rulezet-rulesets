rule VirTool_Win32_CeeInject_TO_bit_4{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 08 80 f3 ?? f6 d3 80 f3 ?? 88 1c 08 } 		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 40 18 } 		$a_03_2 = {73 24 0f b6 55 ?? 8b 45 ?? 8b 08 0f b6 41 ?? 8b 4d ?? 0f b6 54 11 30 33 d0 0f b6 45 ?? 8b 4d ?? 88 54 01 30 } 		$a_03_3 = {52 8b 45 0c 50 8b 4d 08 51 8b 55 10 8b 42 34 50 8b 4d ?? 51 6a 02 8b 55 ?? 8b 42 10 ff d0 b9 4d 5a 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}