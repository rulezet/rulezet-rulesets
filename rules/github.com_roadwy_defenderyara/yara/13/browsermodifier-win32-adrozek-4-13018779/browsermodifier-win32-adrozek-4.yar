rule BrowserModifier_Win32_Adrozek_4{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 30 35 42 38 30 44 45 2d 39 35 46 31 2d 31 31 44 30 2d 42 30 41 30 2d 30 30 41 41 30 30 42 44 43 42 35 43 } 		$a_01_1 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 43 00 4c 00 53 00 49 00 44 00 5c 00 7b 00 34 00 37 00 32 00 30 00 38 00 33 00 42 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}