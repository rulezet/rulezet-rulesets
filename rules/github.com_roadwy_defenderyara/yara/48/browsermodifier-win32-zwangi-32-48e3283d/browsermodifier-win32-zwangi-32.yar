rule BrowserModifier_Win32_Zwangi_32{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b 4d fc ?? ?? ?? 89 4d f4 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 10 50 ff 15 } 		$a_03_1 = {73 21 8b 4d ?? 0f be 11 83 fa 20 74 0b 8b 45 ?? 0f be 08 83 f9 09 75 0b } 		$a_03_2 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3 } 		$a_03_3 = {f7 d9 ff 24 8d ?? ?? 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 ?? 83 e0 03 2b c8 ff 24 85 ?? ?? 40 00 } 		$a_03_4 = {8d 34 40 8d 34 ?? ?? ?? 40 00 2b d0 83 26 00 83 c6 0c 4a 75 ?? 8b 09 81 f9 8e 00 00 c0 8b ?? ?? ?? 40 00 75 ?? c7 05 ?? ?? 40 00 83 00 00 00 eb ?? 81 f9 90 90 00 00 c0 75 ?? c7 05 ?? ?? 40 00 81 00 00 00 eb } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=13
 
}