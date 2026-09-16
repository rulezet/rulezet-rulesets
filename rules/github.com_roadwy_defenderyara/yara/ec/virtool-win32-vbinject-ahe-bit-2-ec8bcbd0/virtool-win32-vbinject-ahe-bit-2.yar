rule VirTool_Win32_VBInject_AHE_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 85 ?? ?? 00 00 [0-40] 41 [0-40] 8b 53 2c [0-40] 31 ca [0-40] 83 fa 00 75 } 		$a_03_1 = {83 fa 00 75 [0-40] 89 ce [0-40] 6a 78 [0-40] 58 [0-40] 31 d2 [0-40] 48 [0-40] 48 [0-40] 48 [0-40] 48 [0-40] 33 14 03 [0-40] e8 ?? ?? ?? ff [0-40] 52 [0-40] 83 f8 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}