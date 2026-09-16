rule BrowserModifier_Win32_Zwangi_35{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_02_0 = {89 45 f8 8b 4d fc 03 4d f8 89 4d f4 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 10 50 ff 15 } 		$a_03_1 = {8b 4d 18 51 8b 55 14 52 8b 45 10 50 8b 4d 0c 51 8b 55 08 52 ff 55 ?? 89 45 ?? eb } 		$a_01_2 = {33 45 10 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc } 		$a_00_3 = {89 45 e8 8b 4d ec 03 4d e8 89 4d e4 8b 55 0c 8b 45 0c 8b 4a 28 2b 48 2c 89 4d fc } 		$a_00_4 = {89 45 bc 8b 4d fc 8b 55 ac 8b 01 33 42 04 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc } 		$a_03_5 = {8d 34 40 8d 34 ?? ?? ?? 40 00 2b d0 83 26 00 83 c6 0c 4a 75 ?? 8b 09 81 f9 8e 00 00 c0 8b ?? ?? ?? 40 00 75 ?? c7 05 ?? ?? 40 00 83 00 00 00 eb ?? 81 f9 90 90 00 00 c0 75 ?? c7 05 ?? ?? 40 00 81 00 00 00 eb } 		$a_03_6 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 ?? ?? ?? ?? 5f 5e 5b c9 c3 } 	condition:
		((#a_02_0  & 1)*10+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=13
 
}