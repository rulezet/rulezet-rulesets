rule BrowserModifier_Win32_Sasquor{
	meta:
		description = "BrowserModifier:Win32/Sasquor,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 63 00 6f 00 2e 00 61 00 6f 00 2e 00 61 00 69 00 6f 00 } 		$a_01_1 = {63 6f 72 65 64 6c 6c 2e 64 6c 6c 00 77 75 77 61 6c 61 6c 61 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}