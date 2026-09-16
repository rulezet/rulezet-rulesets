rule BrowserModifier_Win32_Adrozek_5{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 } 		$a_00_1 = {46 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 5c 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 4d 00 65 00 6e 00 75 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 73 00 5c 00 61 00 76 00 61 00 73 00 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}