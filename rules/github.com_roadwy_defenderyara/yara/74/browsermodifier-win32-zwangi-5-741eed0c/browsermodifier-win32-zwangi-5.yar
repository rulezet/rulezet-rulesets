rule BrowserModifier_Win32_Zwangi_5{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {5d 3e 5d 3e 5d 3e 5d 3e 00 00 00 00 3c 5b 3c 5b 3c 5b 3c 5b } 		$a_01_1 = {83 7d f0 00 76 0c 8b 45 ec 8b 4d 08 8b 11 89 10 eb dc b8 01 00 00 00 c1 e0 02 } 		$a_03_2 = {ff 6a 08 8b 0d 98 ?? 40 00 51 8b 55 fc 52 8b 85 ?? ec ff ff 50 e8 ?? ?? 00 00 83 c4 10 89 85 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}