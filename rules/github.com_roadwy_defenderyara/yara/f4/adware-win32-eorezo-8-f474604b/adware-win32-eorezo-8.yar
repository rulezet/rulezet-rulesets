rule Adware_Win32_Eorezo_8{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c0 e8 04 8a 55 ?? 24 03 c0 e1 02 02 c1 80 e2 0f 88 45 ?? 8a 45 ?? 8a c8 24 03 c0 e9 02 c0 e0 06 02 45 ?? 80 e1 0f c0 e2 04 02 ca } 		$a_03_1 = {8b 45 e0 59 3b c3 59 75 ?? b8 ?? ?? ?? ?? 6a 05 53 68 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 53 } 		$a_01_2 = {61 48 52 30 63 44 6f 76 4c 32 46 6b 63 79 35 79 5a 57 64 70 5a 57 52 6c 63 48 56 69 4c 6d 4e 76 62 53 39 6a 5a 32 6b } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}