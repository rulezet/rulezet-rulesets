rule VirTool_Win32_VBInject_gen_IN{
	meta:
		description = "VirTool:Win32/VBInject.gen!IN,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 4d 36 30 2e 44 4c 4c 00 } 		$a_00_1 = {44 00 3a 00 5c 00 46 00 72 00 61 00 6e 00 6b 00 79 00 5c 00 } 		$a_03_2 = {32 31 41 23 2e 30 40 78 47 72 65 61 74 [0-04] 32 31 41 23 2e 30 40 78 [0-32] 32 31 41 23 2e 30 40 78 } 		$a_03_3 = {ff f5 01 00 00 00 6c 74 ff 9e 2a 31 70 ff 32 04 00 ?? ff ?? ff 00 14 f5 00 00 00 00 6c 74 ff 9e fc 33 f4 01 eb c8 1c } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*5+(#a_03_3  & 1)*1) >=6
 
}