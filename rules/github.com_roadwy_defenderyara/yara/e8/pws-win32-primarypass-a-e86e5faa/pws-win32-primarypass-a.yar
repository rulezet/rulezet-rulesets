rule PWS_Win32_Primarypass_A{
	meta:
		description = "PWS:Win32/Primarypass.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 ee fb ee ab 33 c9 57 0f b6 ?? ?? ?? ?? 00 d1 c0 33 c7 0f b6 ?? ?? ?? ?? 00 d1 c0 33 c7 0f b6 ?? ?? ?? ?? 00 d1 c0 33 c7 0f b6 ?? ?? ?? ?? 00 d1 c0 83 c1 04 33 c7 81 f9 00 01 00 00 72 c9 } 		$a_03_1 = {0f b6 06 4a 33 c8 46 6a 08 58 f6 c1 01 74 06 81 f1 ?? ?? ?? ?? d1 e9 48 75 f0 } 		$a_03_2 = {56 56 68 e2 d4 ea d4 56 e8 ?? ?? ?? ?? 6a 04 68 00 10 00 00 57 56 ff d0 8b d8 85 db 74 38 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}