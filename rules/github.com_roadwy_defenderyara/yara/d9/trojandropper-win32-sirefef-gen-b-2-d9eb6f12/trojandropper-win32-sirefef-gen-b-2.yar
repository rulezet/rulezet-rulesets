rule TrojanDropper_Win32_Sirefef_gen_B_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 72 00 66 00 69 00 65 00 75 00 74 00 69 00 66 00 64 00 6a 00 6c 00 67 00 66 00 6a 00 64 00 6c 00 67 00 00 00 } 		$a_03_1 = {ff d7 85 c0 0f 84 ?? ?? ?? ?? 46 81 fe 03 04 00 00 72 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}