rule VirTool_Win32_VBInject_gen_IN_2{
	meta:
		description = "VirTool:Win32/VBInject.gen!IN,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {0e 00 00 00 50 72 6f 63 65 73 73 33 32 4e 65 78 74 00 } 		$a_03_1 = {ff f5 01 00 00 00 6c 74 ff 9e 2a 31 70 ff 32 04 00 ?? ff ?? ff 00 14 f5 00 00 00 00 6c 74 ff 9e fc 33 f4 01 eb c8 1c } 		$a_03_2 = {33 31 42 2a 2e 31 40 79 (90 04 06 06 61 2d 7a 41 2d 5a|?? 90 03) 01 01 3a 23 33 31 42 2a 2e 31 40 79 [0-32] 90 03 01 01 3a 23 33 31 42 2a 2e 31 40 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}