rule BrowserModifier_Win32_Zwangi_14{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a4 00 00 00 05 a0 00 00 00 85 d2 76 ?? 8b 51 04 57 8b 38 8b 04 3a 03 d7 85 c0 76 ?? 53 55 56 8b 71 04 03 f0 8b 42 04 83 e8 08 33 db a9 fe ff ff ff 8d 7a 08 76 ?? 8d 9b 00 00 00 00 33 c0 66 8b 07 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00 } 		$a_03_1 = {8b 74 24 20 66 81 3e 4d 5a c6 44 24 18 01 74 0c 68 ?? ?? 00 10 8b cf e8 ?? ?? ?? ?? 53 8b 5e 3c 8b 04 33 03 de 3d 50 45 00 00 74 0c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}