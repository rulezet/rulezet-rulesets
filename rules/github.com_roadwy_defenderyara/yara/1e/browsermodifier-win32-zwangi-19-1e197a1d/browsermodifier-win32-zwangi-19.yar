rule BrowserModifier_Win32_Zwangi_19{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 80 02 00 00 [0-05] 8b 15 ?? 72 40 00 } 		$a_03_1 = {55 8b ec 81 ec 80 02 00 00 0f b6 ?? a8 72 40 00 85 ?? 74 } 		$a_03_2 = {c7 05 a0 72 40 00 00 00 00 00 (eb|e9) } 		$a_03_3 = {a1 a4 72 40 00 0f be 08 83 f9 22 75 ?? 8b 0d a4 72 40 00 83 c1 01 } 		$a_03_4 = {f7 d9 ff 24 8d ?? ?? 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 ?? 83 e0 03 2b c8 ff 24 85 ?? ?? 40 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}