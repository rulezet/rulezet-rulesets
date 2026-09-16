rule VirTool_Win32_VBInject_AHI{
	meta:
		description = "VirTool:Win32/VBInject.AHI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 65 b0 00 8d 45 b0 50 6a 08 8d 45 e4 50 ff 75 0c 6a ff e8 } 		$a_01_1 = {68 10 00 00 00 8b c4 50 8d 44 24 0c 50 b9 ad 14 4a 73 ff d1 59 0b c0 78 0c 8b 44 24 04 8b 00 ff a0 40 00 00 00 5a 03 e1 52 c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}