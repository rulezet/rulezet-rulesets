rule BrowserModifier_Win32_Zwangi_15{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {04 e0 80 f9 61 7c 08 80 f9 7a 7f 03 80 c1 e0 3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 33 d2 3a c1 0f 94 c2 8a c2 5e c3 } 		$a_00_1 = {01 28 8b 42 04 83 e8 08 43 d1 e8 83 c7 02 3b d8 72 } 		$a_01_2 = {99 f7 fd 33 c0 8a 04 1a 33 d2 8a 11 03 d7 03 c2 25 ff 00 00 00 8b f8 8a 14 37 8a 01 88 04 37 } 		$a_03_3 = {74 17 8a 46 01 80 e9 ?? 46 84 c0 74 33 2c ?? b3 ?? f6 eb 02 c8 8b 44 24 ?? 8b 5c 24 ?? 2a ca } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}