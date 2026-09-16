rule BrowserModifier_Win32_Zwangi_28{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 e0 02 00 00 00 8b 55 0c 8b 42 04 89 45 e8 8b 4d e8 89 4d f0 8b 55 f0 89 55 e4 8b 45 e0 8b 4d e4 8d 14 81 89 55 e4 8b 45 e4 89 45 ec 8b 4d ec 8b 11 52 ff 55 08 e9 15 01 00 00 } 		$a_03_1 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 ?? ?? 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 ?? ?? 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 ?? ?? 00 00 } 		$a_03_2 = {6a 00 6a 00 8b 55 c8 52 ff 15 ?? ?? ?? ?? 89 45 d4 } 		$a_03_3 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 ?? ?? 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 ?? ?? 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 ?? ?? 00 00 8b 4d cc } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}