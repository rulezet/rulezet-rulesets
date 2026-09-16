rule BrowserModifier_Win32_Startpage{
	meta:
		description = "BrowserModifier:Win32/Startpage,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {86 51 e9 b6 85 3c 5b 5f 33 c9 59 bd 5f 28 73 99 4e 25 64 6e 61 24 a8 61 75 3f aa ee 34 } 		$a_01_1 = {8b 4c 24 08 8a 01 56 2c 39 57 8b 7c 24 0c 0f b6 f0 56 8d 41 01 50 57 6a 01 51 e8 27 ff ff ff 83 c4 14 c6 44 3e ff 00 8b c7 5f 5e c3 } 		$a_01_2 = {2c 44 6c 6c 49 6e 73 74 61 6c 6c } 		$a_02_3 = {73 65 61 72 63 68 2d 70 69 6e 28 [0-04] 29 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_02_3  & 1)*2) >=6
 
}