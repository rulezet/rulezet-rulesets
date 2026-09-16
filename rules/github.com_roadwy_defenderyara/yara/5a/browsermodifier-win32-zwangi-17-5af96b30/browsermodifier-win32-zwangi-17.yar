rule BrowserModifier_Win32_Zwangi_17{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b c1 8d a4 24 00 00 00 00 8a 50 01 40 84 d2 75 ?? 2d } 		$a_02_1 = {50 8b f0 ff d7 8d 0c 30 8d 80 ?? ?? ?? ?? 3d ?? ?? ?? ?? 72 ?? 2b c8 eb ?? 8d 49 00 } 		$a_02_2 = {f7 d8 1b c0 83 e0 07 40 f7 c3 00 00 00 04 74 ?? 0d 00 02 00 00 } 		$a_01_3 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 } 		$a_03_4 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}