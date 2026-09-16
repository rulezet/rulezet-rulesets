rule BrowserModifier_Win32_Zwangi_11{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 84 c0 75 06 b8 01 00 00 00 c3 6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 85 c0 75 06 b8 02 00 00 00 c3 ff e0 } 		$a_03_1 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3 } 		$a_03_2 = {2b f0 8a 50 ff 48 3b c1 88 14 06 ?? f5 } 		$a_01_3 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}