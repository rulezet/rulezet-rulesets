rule VirTool_Win32_VBInject_OS_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 ff 35 30 00 00 00 [0-30] 58 [0-30] 8b 40 0c [0-30] 8b 40 14 } 		$a_03_1 = {81 3b 4d 00 53 00 75 [0-30] 81 7b 04 56 00 42 00 75 [0-30] 8b 70 10 [0-30] 8b 5e 3c [0-30] 01 de [0-30] [0-30] 8b 5e 78 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}