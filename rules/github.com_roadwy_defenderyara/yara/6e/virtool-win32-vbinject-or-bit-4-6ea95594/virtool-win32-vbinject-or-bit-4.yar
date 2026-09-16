rule VirTool_Win32_VBInject_OR_bit_4{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ad 83 f8 00 74 ?? bb 57 8b ec 83 4b 4b 39 18 75 ?? bb ee 0c 56 8d 4b 4b 39 58 04 } 		$a_03_1 = {c6 04 24 48 [0-10] c6 44 24 01 65 [0-10] c6 44 24 02 61 [0-10] c6 44 24 03 70 [0-10] c6 44 24 04 43 [0-10] c6 44 24 05 72 [0-10] c6 44 24 06 65 [0-10] c6 44 24 07 61 [0-10] c6 44 24 08 74 [0-10] c6 44 24 09 65 } 		$a_03_2 = {ff 34 08 e9 ?? ?? ?? ?? 8f 04 08 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}