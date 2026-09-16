rule VirTool_Win32_CeeInject_OB_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.OB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 1f 03 d1 8b fa 8d 14 f6 8d 04 d6 8a 4c 3c 10 c1 e0 04 03 c6 80 f1 ec 8d 34 c0 b8 63 20 d5 31 f7 ee c1 fa 0b 8b c2 c1 e8 1f 03 d0 88 8c 14 dc 0a 00 00 8a 84 3c dc 0a 00 00 } 		$a_01_1 = {6d 65 6e 67 79 75 77 6f 72 6b 72 6f 6f 6d 2e 79 33 36 35 2e 63 6f 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}