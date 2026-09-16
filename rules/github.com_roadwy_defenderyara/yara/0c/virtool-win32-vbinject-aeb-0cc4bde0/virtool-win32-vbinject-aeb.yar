rule VirTool_Win32_VBInject_AEB{
	meta:
		description = "VirTool:Win32/VBInject.AEB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 74 ff 6c 74 ff 1b 06 00 2a 31 74 ff 6c 74 ff 1b 07 00 2a 31 74 ff 6c 74 ff 1b 08 00 2a 31 74 ff 6c 74 ff 1b 09 00 2a 31 74 ff 6c 74 ff 1b 0a 00 2a 31 74 ff 6c 74 ff 1b 0b 00 2a 31 74 ff 6c 74 ff 1b 0c 00 2a 31 74 ff 6c 74 ff 1b 0d 00 2a 31 74 ff } 		$a_01_1 = {38 00 31 00 37 00 43 00 31 00 44 00 46 00 43 00 34 00 33 00 34 00 33 00 } 		$a_01_2 = {38 00 31 00 46 00 39 00 38 00 35 00 43 00 30 00 38 00 35 00 43 00 30 00 } 		$a_01_3 = {34 00 30 00 33 00 31 00 43 00 31 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}