rule BrowserModifier_Win32_Zwangi_21{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 55 dc 81 3a 50 45 00 00 74 } 		$a_01_1 = {8b 55 dc 81 3a 50 45 00 00 0f } 		$a_01_2 = {5d 3e 5d 3e 5d 3e 5d 3e } 		$a_03_3 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 [0-04] 4c 6f 63 6b 52 65 73 6f 75 72 63 65 [0-04] 4c 6f 61 64 52 65 73 6f 75 72 63 65 [0-04] 46 69 6e 64 52 65 73 6f 75 72 63 65 41 } 		$a_01_4 = {00 42 49 4e 00 } 		$a_03_5 = {74 23 6a 04 68 00 20 00 00 8b 85 ?? ?? ff ff 50 8b 8d ?? ?? ff ff 51 ff 95 ?? ?? ff ff 89 85 ?? ?? ff ff eb 0a } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*5+(#a_03_5  & 1)*5) >=11
 
}