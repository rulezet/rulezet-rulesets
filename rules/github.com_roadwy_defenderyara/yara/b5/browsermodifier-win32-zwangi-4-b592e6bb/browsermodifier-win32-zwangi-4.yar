rule BrowserModifier_Win32_Zwangi_4{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 1c c6 85 ?? ?? ff ff 22 8b 4d fc 83 c1 01 8b 95 ?? ?? ff ff 89 8c 95 } 		$a_03_1 = {eb 12 8b 8d ?? ?? ff ff 8b 55 fc 89 94 8d ?? ?? ff ff eb 09 c6 85 ?? ?? ff ff 20 eb } 		$a_01_2 = {83 c4 04 f7 d8 eb 1a 0f b6 4d 0c 85 c9 74 0e 8b 4d 08 51 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}