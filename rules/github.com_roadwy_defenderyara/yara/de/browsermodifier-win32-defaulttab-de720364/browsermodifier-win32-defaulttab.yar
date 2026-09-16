rule BrowserModifier_Win32_DefaultTab{
	meta:
		description = "BrowserModifier:Win32/DefaultTab,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 66 61 75 6c 74 54 61 62 53 65 61 72 63 68 } 		$a_01_1 = {61 70 69 2e 64 65 66 61 75 6c 74 74 61 62 2e 63 6f 6d 2f 74 6f 6f 6c 62 61 72 2f 6f 70 65 6e } 		$a_03_2 = {53 6f 66 74 77 61 72 65 5c 44 65 66 61 75 6c 74 20 54 61 62 5c 50 [0-06] 61 66 66 69 64 00 00 00 75 69 64 } 		$a_01_3 = {73 65 74 5f 68 6f 6d 65 5f 70 61 67 65 5f 6f 6e 5f 75 70 64 61 74 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}