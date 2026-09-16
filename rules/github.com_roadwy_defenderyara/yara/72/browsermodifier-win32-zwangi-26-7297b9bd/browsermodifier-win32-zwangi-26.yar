rule BrowserModifier_Win32_Zwangi_26{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 44 24 08 8b 4c 24 04 f6 d8 55 56 57 1b c0 25 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8d 6c 08 ff 3b cd be ?? ?? ?? ?? bf ?? ?? ?? ?? 73 48 53 } 		$a_03_1 = {33 c9 83 f8 06 0f 95 c1 49 83 e1 c4 83 c1 40 8b c1 f7 ?? 00 00 00 04 } 		$a_03_2 = {56 8b f1 57 8b 3e 85 ff 74 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 50 8b 06 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 57 ff d0 5f 5e c3 } 		$a_03_3 = {0f be c0 83 e8 61 b3 1a f6 eb [0-04] 02 c2 2c 61 41 eb 02 } 		$a_03_4 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}