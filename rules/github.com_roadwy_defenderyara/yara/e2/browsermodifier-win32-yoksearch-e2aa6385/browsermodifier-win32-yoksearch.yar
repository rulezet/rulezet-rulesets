rule BrowserModifier_Win32_YokSearch{
	meta:
		description = "BrowserModifier:Win32/YokSearch,SIGNATURE_TYPE_PEHSTR,08 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {79 6f 6b 2e 64 6c 6c } 		$a_01_1 = {79 6f 6b 2e 65 78 65 } 		$a_01_2 = {59 4f 4b 2e 69 63 6f } 		$a_01_3 = {59 4f 4b 55 50 44 57 43 6c 61 73 73 } 		$a_01_4 = {77 77 77 2e 79 6f 6b 2e 63 6f 6d 2f 67 6f } 		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 59 4f 4b 5c 43 6f 6f 70 } 		$a_01_6 = {53 6f 66 74 57 61 72 65 5c 59 6f 6b 5c 54 6f 6f 6c 62 61 72 } 		$a_01_7 = {5c 79 6f 6b 73 63 68 2e 68 74 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}