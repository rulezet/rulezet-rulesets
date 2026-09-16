rule TrojanDropper_Win32_Sirefef_B_5{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 70 58 85 f6 75 ?? be 53 50 43 33 e8 } 		$a_00_1 = {b8 00 51 00 00 66 89 44 24 30 b8 00 52 00 00 66 89 44 24 32 b8 00 50 00 00 66 89 44 24 34 b8 73 72 00 00 66 89 44 24 36 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}