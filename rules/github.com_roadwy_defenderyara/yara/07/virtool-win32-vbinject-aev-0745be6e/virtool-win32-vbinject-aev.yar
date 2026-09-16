rule VirTool_Win32_VBInject_AEV{
	meta:
		description = "VirTool:Win32/VBInject.AEV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bf 74 23 11 00 c7 43 34 04 00 00 00 39 7b 34 0f 8f 1f 01 00 00 51 51 d9 e8 dd 1c 24 e8 d2 a1 fe ff dd d8 } 		$a_01_1 = {c7 81 98 09 00 00 2d 51 a4 3b 8b 48 54 c7 81 68 13 00 00 f1 b9 66 0f 8b 48 54 c7 81 dc 13 00 00 74 c7 0f d8 8b 48 54 c7 81 98 11 00 00 d6 ae a4 c7 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}