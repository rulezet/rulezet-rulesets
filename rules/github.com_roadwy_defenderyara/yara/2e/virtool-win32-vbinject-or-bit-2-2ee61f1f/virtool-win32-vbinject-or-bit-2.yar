rule VirTool_Win32_VBInject_OR_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ad 83 f8 00 74 fa bb 57 8b ec 83 4b 4b 39 18 75 ef bb ee 0c 56 8d 4b 4b 39 58 04 75 e3 } 		$a_03_1 = {6a 00 6a 00 6a 01 81 04 24 ?? ?? 00 00 ff d0 89 45 08 89 f9 eb } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}