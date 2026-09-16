rule BrowserModifier_Win32_Zwangi_22{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 70 74 61 67 3d 00 } 		$a_01_1 = {26 70 61 72 74 6e 65 72 3d 00 } 		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 3f 25 73 3d 25 64 00 } 		$a_03_3 = {8d 44 24 10 81 c6 ?? ?? 00 00 50 8b ce c7 44 24 14 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4c 24 10 51 8b ce c7 44 24 14 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 54 24 10 } 		$a_03_4 = {8b 59 04 85 db c7 44 24 18 00 00 00 00 75 04 33 c0 eb 18 8b 71 08 2b f3 b8 ?? ?? ?? ?? f7 ee 03 d6 c1 fa 04 8b c2 c1 e8 1f 03 c2 8b 7c 24 20 3b c7 73 33 85 db 75 04 33 c0 eb 18 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}