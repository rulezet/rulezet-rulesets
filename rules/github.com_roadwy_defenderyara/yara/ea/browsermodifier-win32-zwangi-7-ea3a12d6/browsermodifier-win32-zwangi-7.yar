rule BrowserModifier_Win32_Zwangi_7{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c3 83 f8 05 75 06 b8 80 00 00 00 c3 3d } 		$a_01_1 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e } 		$a_03_2 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3 } 		$a_03_3 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f [0-20] 01 00 00 00 09 00 00 00 09 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}