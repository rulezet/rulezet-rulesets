rule TrojanDropper_Win32_Sirefef_B_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 f1 2e 8e 40 42 35 47 42 ca 72 89 4d f0 8b 0d ?? ?? 40 00 89 45 ec a1 ?? ?? 40 00 81 f1 0a 30 76 9d 35 88 b3 5e bb 89 4d f8 32 c9 } 		$a_02_1 = {01 00 00 9d 90 90 68 ?? ?? 41 00 6a 00 6a 00 68 ?? ?? 41 00 6a fe ff 15 ?? ?? 41 00 } 		$a_00_2 = {5a 77 51 75 65 75 65 41 70 63 54 68 72 65 61 64 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}