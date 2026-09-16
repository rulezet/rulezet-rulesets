rule VirTool_Win32_VBInject_gen_HT_2{
	meta:
		description = "VirTool:Win32/VBInject.gen!HT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {bb e9 00 00 00 8b c1 83 c4 1c 99 f7 fb 8b c1 } 		$a_03_1 = {05 f8 00 00 00 6a 28 0f 80 ?? ?? 00 00 6b c9 28 } 		$a_01_2 = {8d 85 30 fd ff ff 50 56 56 6a 04 56 56 56 8d 8d 14 fd ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}