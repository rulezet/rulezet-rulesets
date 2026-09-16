rule BrowserModifier_Win32_Monkostey{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 68 74 74 70 3a 2f 2f 75 6e 69 6e 73 74 61 6c 6c 2e 6d 79 73 61 66 65 73 61 76 69 6e 67 73 2e 63 6f 6d } 		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 4c 6f 67 67 65 72 5c 77 69 6e 6c 6f 67 67 65 72 2e 65 78 65 } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 79 53 61 66 65 53 61 76 69 6e 67 73 } 		$a_01_3 = {67 72 69 6c 00 46 69 6e 64 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}