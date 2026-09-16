rule BrowserModifier_Win32_Pointfree_2{
	meta:
		description = "BrowserModifier:Win32/Pointfree,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 70 6f 69 6e 74 66 72 65 65 2e 63 6f 2e 6b 72 2f 61 70 70 2f 72 65 6d 6f 76 65 2e 70 68 70 } 		$a_01_1 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } 		$a_01_2 = {26 6d 32 63 6f 64 65 3d 25 73 } 		$a_01_3 = {52 65 63 6f 76 65 72 79 45 78 65 4e 61 6d 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}