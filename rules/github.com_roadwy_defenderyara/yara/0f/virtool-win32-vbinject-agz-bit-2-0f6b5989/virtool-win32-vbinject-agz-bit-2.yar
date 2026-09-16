rule VirTool_Win32_VBInject_AGZ_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 [0-10] 8b 40 0c [0-10] 8b 40 14 [0-10] 8b 40 14 [0-10] 48 66 81 38 ff 25 75 ?? e9 } 		$a_01_1 = {40 81 38 8b 7c 24 0c 75 f7 81 78 04 85 ff 7c 08 75 ee } 		$a_03_2 = {5f 81 34 1f [0-15] 66 39 d3 [0-10] 75 [0-10] ff e0 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}