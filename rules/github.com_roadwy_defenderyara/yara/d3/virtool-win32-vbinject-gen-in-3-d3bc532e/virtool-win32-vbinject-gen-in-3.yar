rule VirTool_Win32_VBInject_gen_IN_3{
	meta:
		description = "VirTool:Win32/VBInject.gen!IN,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff f5 01 00 00 00 6c 74 ff 9e 2a 31 70 ff 32 04 00 ?? ff ?? ff 00 14 f5 00 00 00 00 6c 74 ff 9e fc 33 f4 01 eb c8 1c } 		$a_03_1 = {59 6f 75 41 6c 6c 41 76 53 75 63 6b 4d 79 44 69 63 6b 46 69 6e 61 6c 6c 79 3a 29 ?? 59 6f 75 41 6c 6c 41 76 53 75 63 6b 4d 79 44 69 63 6b 46 69 6e 61 6c 6c 79 3a 29 [0-32] 59 6f 75 41 6c 6c 41 76 } 		$a_03_2 = {2e 2e 23 23 ae a9 33 32 35 35 39 5e 24 24 ?? 2e 2e 23 23 ae a9 33 32 35 35 39 } 		$a_01_3 = {1e 28 32 3c 46 50 5a 64 32 1e 28 32 3c 46 50 5a } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}