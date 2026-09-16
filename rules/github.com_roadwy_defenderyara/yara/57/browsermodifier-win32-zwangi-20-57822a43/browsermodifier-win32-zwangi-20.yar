rule BrowserModifier_Win32_Zwangi_20{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8b 55 10 52 e8 ?? ?? ff ff 83 c4 08 } 		$a_03_1 = {a8 72 40 00 85 ?? 74 ?? 83 7d 0c 00 75 09 ?? 01 00 00 00 85 ?? 74 09 8b ?? 0c 89 ?? a0 72 40 00 e9 } 		$a_03_2 = {8b 76 0c 81 e6 ff 7f 00 00 89 35 ?? ?? ?? ?? 83 f9 02 74 ?? 81 ce 00 80 00 00 89 35 ?? ?? ?? ?? c1 e0 08 03 c2 a3 ?? ?? ?? ?? 33 f6 56 8b 3d ?? ?? ?? ?? ff } 		$a_01_3 = {8b 15 a4 72 40 00 0f be 02 85 c0 75 } 		$a_01_4 = {8b 0d a4 72 40 00 0f be 11 85 d2 75 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}