rule BrowserModifier_Win32_Zwangi_13{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 ec 74 01 00 00 e9 ?? ?? ?? ?? 8b 55 10 89 15 a4 72 40 00 eb ?? 83 7d ec 00 75 ?? 8b 4d e8 51 ff 55 f8 e9 } 		$a_03_1 = {c7 05 a0 72 40 00 00 00 00 00 (eb|e9) } 		$a_03_2 = {0f be 02 83 f8 22 75 5a eb ?? eb } 		$a_03_3 = {f7 d9 ff 24 8d ?? ?? 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 ?? 83 e0 03 2b c8 ff 24 85 ?? ?? 40 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}