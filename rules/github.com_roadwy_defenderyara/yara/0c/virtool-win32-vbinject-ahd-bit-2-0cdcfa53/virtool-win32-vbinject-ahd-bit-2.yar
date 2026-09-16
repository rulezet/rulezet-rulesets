rule VirTool_Win32_VBInject_AHD_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 18 00 00 00 [0-40] 64 8b 00 [0-40] 8b 40 30 [0-40] 5b [0-40] 02 58 02 [0-40] ff e3 } 		$a_03_1 = {83 f9 00 75 [0-40] ff e0 } 		$a_03_2 = {81 eb 00 10 00 00 [0-40] 53 [0-40] 6a 00 [0-40] 6a 00 [0-40] ff 72 68 [0-40] ff 72 6c [0-40] ff 72 70 [0-40] ff 72 74 [0-40] 6a 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}