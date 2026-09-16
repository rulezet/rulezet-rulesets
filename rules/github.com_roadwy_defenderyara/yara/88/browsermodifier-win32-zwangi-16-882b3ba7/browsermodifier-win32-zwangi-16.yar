rule BrowserModifier_Win32_Zwangi_16{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {50 57 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 8b 4c 24 10 6a 04 68 00 10 00 00 51 56 ff d0 8b f8 eb 02 33 ff 8b 4c 24 10 8b d1 c1 e9 02 33 c0 89 7b f8 f3 ab } 		$a_01_1 = {8a 0f 84 c9 74 15 2a 0a 46 88 4e ff 8a 4a 01 42 84 c9 75 02 8b d5 47 3b fb 72 e5 } 		$a_03_2 = {84 c0 74 14 8b 0d ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 08 b8 01 00 00 00 c2 04 00 ff e0 } 		$a_00_3 = {42 49 4e 00 53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } 	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}