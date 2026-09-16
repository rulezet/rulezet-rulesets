rule BrowserModifier_Win32_Sasquor_2{
	meta:
		description = "BrowserModifier:Win32/Sasquor,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 61 6d 75 6c 65 63 75 73 74 6f 6d 5c 62 69 6b 61 51 5c 52 65 6c 65 61 73 65 5c 75 70 64 61 74 65 2e 70 64 62 } 		$a_01_1 = {5c 61 6d 75 6c 65 63 75 73 74 6f 6d 5c 61 6d 75 6c 65 5c 75 70 64 61 74 65 5c 52 65 6c 65 61 73 65 5c 75 70 64 61 74 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}