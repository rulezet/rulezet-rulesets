rule BrowserModifier_Win32_Zwangi_8{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 81 80 13 00 00 8b 54 81 fc 8b fa c1 ef 1e 33 fa 69 ff 65 89 07 6c 03 f8 89 3c 81 8b 91 80 13 00 00 42 8b c2 3d 70 02 00 00 89 91 80 13 00 00 7c ce } 		$a_01_1 = {8b 55 ec 3b 55 f4 74 6a 8b 45 fc 83 c0 01 25 ff 00 00 00 89 45 fc } 		$a_00_2 = {3c 26 74 04 3c 3d 75 02 b0 5f } 		$a_00_3 = {3c 3d 74 04 3c 26 75 02 b0 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}