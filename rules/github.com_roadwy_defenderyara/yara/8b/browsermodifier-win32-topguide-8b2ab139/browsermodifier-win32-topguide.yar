rule BrowserModifier_Win32_TopGuide{
	meta:
		description = "BrowserModifier:Win32/TopGuide,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 53 6d 61 72 74 54 6f 6f 6c 00 } 		$a_01_1 = {53 6d 61 72 74 54 6f 6f 6c 2e 64 6c 6c 00 } 		$a_01_2 = {2e 70 6c 75 73 74 61 62 2e 63 6f 2e 6b 72 2f 75 70 64 61 74 65 2f 00 } 		$a_01_3 = {73 68 6f 70 2e 63 6f 6d 2f 73 65 61 72 63 68 2f } 		$a_01_4 = {2f 74 6f 70 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 62 61 72 2e 61 73 70 3f 6b 3d 25 73 26 69 64 3d 25 73 26 6d 3d 25 73 } 		$a_01_5 = {53 45 41 52 43 48 5f 4b 45 59 57 4f 52 44 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}