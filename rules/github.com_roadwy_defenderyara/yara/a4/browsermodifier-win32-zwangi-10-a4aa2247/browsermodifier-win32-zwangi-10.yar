rule BrowserModifier_Win32_Zwangi_10{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f be c0 83 e8 61 b3 1a f6 eb 02 c2 2c 61 41 } 		$a_03_1 = {8a 44 24 08 8b 4c 24 04 f6 d8 55 56 57 1b c0 25 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8d 6c 08 ff 3b cd } 		$a_03_2 = {b0 01 5b 59 c3 8b cd e8 ?? ?? ?? ?? 5f 5e c6 45 ?? 01 5d 32 c0 } 		$a_03_3 = {8b c1 99 f7 7c 24 50 33 c0 8a 04 2a 33 d2 8a 91 ?? ?? ?? ?? 03 d6 03 c2 25 ff 00 00 00 8b f0 3b ce 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}