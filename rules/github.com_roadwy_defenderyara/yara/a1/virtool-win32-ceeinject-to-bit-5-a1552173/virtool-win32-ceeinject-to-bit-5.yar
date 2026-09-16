rule VirTool_Win32_CeeInject_TO_bit_5{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {fe c3 0f b6 f3 8a 14 3e 02 fa 0f b6 cf 8a 04 39 88 04 3e 88 14 39 0f b6 0c 3e 0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 8a 04 38 30 04 29 45 3b 6c 24 14 72 } 		$a_03_1 = {0f b6 04 1f 33 c1 c1 e9 08 0f b6 c0 33 0c 85 ?? ?? ?? ?? 47 3b fa 72 e8 } 		$a_03_2 = {8b 0b 8b f1 8b 53 ?? 8d 5b ?? 8b c1 c1 c6 0f c1 c0 0d 33 f0 c1 e9 0a 33 f1 8b c2 8b ca c1 c8 07 c1 c1 0e 33 c8 c1 ea 03 33 ca 03 f1 03 73 ?? 03 73 ?? 89 73 ?? 83 ed 01 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}