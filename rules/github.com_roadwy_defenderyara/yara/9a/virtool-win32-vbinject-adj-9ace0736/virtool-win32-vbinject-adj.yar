rule VirTool_Win32_VBInject_ADJ{
	meta:
		description = "VirTool:Win32/VBInject.ADJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {b8 fc fd fe ff } 		$a_01_1 = {2d 04 04 04 04 } 		$a_00_2 = {6e 6f 72 74 6f 6e } 		$a_00_3 = {0f b7 47 14 } 		$a_00_4 = {bb 00 00 40 00 } 		$a_00_5 = {66 3b 77 06 } 		$a_03_6 = {0b c0 74 02 ff e0 68 ?? ?? 40 00 b8 ?? ?? 40 00 ff d0 ff e0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*1) >=3
 
}