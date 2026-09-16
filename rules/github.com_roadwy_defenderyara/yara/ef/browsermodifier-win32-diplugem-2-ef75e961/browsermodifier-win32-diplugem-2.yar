rule BrowserModifier_Win32_Diplugem_2{
	meta:
		description = "BrowserModifier:Win32/Diplugem,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 ff 2b d1 89 45 fc 53 3b f7 75 02 33 f6 8a 04 0a 8b 5d 08 32 04 1e 46 88 01 41 ff 4d fc 75 e8 5b } 		$a_01_1 = {25 73 3f 71 3d 25 30 38 58 26 74 3d 25 30 38 58 26 70 3d 25 64 26 76 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}