rule BrowserModifier_Win32_Zwangi_29{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 0f 84 c9 74 15 2a 0a 46 88 4e ff 8a 4a 01 42 84 c9 75 02 8b d5 47 3b fb 72 e5 } 		$a_03_1 = {84 c0 74 14 8b 0d ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff 85 c0 75 08 b8 01 00 00 00 c2 04 00 ff e0 90 09 05 00 e8 ?? ?? ff ff } 		$a_03_2 = {eb 02 33 c9 68 ?? ?? 00 10 89 0d 04 ?? 00 10 89 5d fc e8 ?? ?? ff ff 3b c3 74 36 } 		$a_03_3 = {74 16 8b 0d ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff 85 c0 74 02 ff e0 33 c0 c2 0c 00 } 		$a_03_4 = {c7 44 24 14 ff ff ff ff 74 21 6a 00 6a 00 68 10 a1 00 10 68 ?? a1 00 10 e8 6f 03 00 00 83 c4 10 50 56 ff d7 85 c0 74 03 56 ff d0 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=10
 
}