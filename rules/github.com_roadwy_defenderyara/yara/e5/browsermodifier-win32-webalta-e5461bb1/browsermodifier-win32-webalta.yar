rule BrowserModifier_Win32_Webalta{
	meta:
		description = "BrowserModifier:Win32/Webalta,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 53 65 61 72 63 68 53 65 72 76 69 63 65 } 		$a_01_1 = {57 65 62 61 6c 74 61 53 65 72 76 69 63 65 } 		$a_01_2 = {50 24 72 6f 24 63 65 73 73 } 		$a_01_3 = {44 24 6f 77 6e 24 6c 6f 61 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}