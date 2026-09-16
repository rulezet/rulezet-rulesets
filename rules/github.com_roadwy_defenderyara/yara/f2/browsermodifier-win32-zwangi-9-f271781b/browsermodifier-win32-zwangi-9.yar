rule BrowserModifier_Win32_Zwangi_9{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {f7 d8 1b c0 83 e0 70 83 c0 10 eb ?? f7 c1 00 00 00 40 } 		$a_03_1 = {8a 14 01 88 10 48 3d ?? ?? ?? ?? 73 ?? 68 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? ff d6 } 		$a_01_2 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 } 		$a_03_3 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}