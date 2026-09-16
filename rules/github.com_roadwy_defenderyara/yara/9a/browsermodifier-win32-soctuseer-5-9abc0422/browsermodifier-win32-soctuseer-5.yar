rule BrowserModifier_Win32_Soctuseer_5{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 73 6b 61 72 73 6e 69 6b 00 } 		$a_01_1 = {77 61 6a 61 6d 5f 67 6f 62 6c 69 6e 5f 36 34 2e 70 64 62 } 		$a_01_2 = {53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 } 		$a_01_3 = {53 00 6f 00 63 00 69 00 61 00 32 00 53 00 65 00 61 00 72 00 63 00 68 00 } 	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*50+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=101
 
}