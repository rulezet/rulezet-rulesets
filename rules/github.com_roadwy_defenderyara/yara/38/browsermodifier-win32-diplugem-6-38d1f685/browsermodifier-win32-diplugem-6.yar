rule BrowserModifier_Win32_Diplugem_6{
	meta:
		description = "BrowserModifier:Win32/Diplugem,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 49 01 29 c8 25 ff 00 00 00 88 c2 8b 45 ?? 89 c1 81 c1 01 00 00 00 89 4d ?? 88 10 } 		$a_03_1 = {0f b6 52 01 29 d0 25 ff 00 00 00 88 c1 8b 45 ?? 89 c2 81 c2 01 00 00 00 89 55 ?? 88 08 } 		$a_03_2 = {89 e2 8d 75 ?? 89 72 0c 89 0a c7 42 08 40 00 00 00 c7 42 04 00 10 00 00 8b 0d ?? ?? ?? ?? 89 45 ?? ff d1 83 ec 10 8b 0d ?? ?? ?? ?? ba 00 10 00 00 8b 75 ?? 8b 7d ?? 89 34 24 89 7c 24 04 c7 44 24 08 00 10 00 00 } 		$a_01_3 = {c1 e9 02 fc f3 a5 8b 44 24 04 8b 64 24 08 89 44 24 20 9d 61 ff e0 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}