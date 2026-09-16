rule VirTool_Win32_VBInject_OR_bit_3{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 30 00 00 00 [0-20] 64 ff 30 [0-30] 58 [0-20] 8b 40 0c [0-20] 8b 40 14 } 		$a_03_1 = {c6 83 eb 04 [0-20] 8b 14 1f [0-20] 31 f2 [0-30] 89 14 18 [0-20] 85 db 75 [0-20] ff e0 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}