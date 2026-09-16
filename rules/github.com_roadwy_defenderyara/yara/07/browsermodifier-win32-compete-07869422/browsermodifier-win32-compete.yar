rule BrowserModifier_Win32_Compete{
	meta:
		description = "BrowserModifier:Win32/Compete,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 72 61 74 65 64 20 62 79 20 43 6f 6d 70 65 74 65 2c 20 49 6e 63 2e } 		$a_01_1 = {6f 70 65 6e 20 68 74 74 70 3a 2f 2f 63 6f 6e 73 75 6d 65 72 69 6e 70 75 74 2e 63 6f 6d 2f 70 72 69 76 61 63 79 } 		$a_01_2 = {24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}