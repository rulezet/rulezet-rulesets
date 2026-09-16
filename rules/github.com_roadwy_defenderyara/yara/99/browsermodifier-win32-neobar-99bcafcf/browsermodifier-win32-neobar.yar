rule BrowserModifier_Win32_Neobar{
	meta:
		description = "BrowserModifier:Win32/Neobar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 00 00 } 		$a_01_1 = {2f 00 6e 00 72 00 70 00 00 00 } 		$a_01_2 = {2f 00 65 00 78 00 62 00 00 00 } 		$a_01_3 = {43 00 68 00 72 00 6f 00 6d 00 69 00 75 00 6d 00 2e 00 64 00 6c 00 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}