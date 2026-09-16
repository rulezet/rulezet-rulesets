rule BrowserModifier_Win32_Sasquor_3{
	meta:
		description = "BrowserModifier:Win32/Sasquor,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 73 72 63 5c 6f 75 74 5c 52 65 6c 65 61 73 65 5c 73 65 74 75 70 2e 70 64 62 } 		$a_01_1 = {73 65 74 75 70 2e 64 6c 6c 00 44 6c 6c 45 6e 74 72 79 00 } 		$a_01_2 = {43 00 52 00 5f 00 4b 00 59 00 33 00 46 00 } 		$a_01_3 = {48 00 39 00 4b 00 32 00 2e 00 54 00 4d 00 50 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}