rule BrowserModifier_Win32_Zwangi_3{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 3e 2d 75 64 8a 46 01 3c 78 75 5d 80 7e 02 72 75 2c } 		$a_01_1 = {2d 52 00 00 2d 72 00 } 		$a_01_2 = {5d 3e 5d 3e 5d 3e 5d 3e } 		$a_01_3 = {3c 5b 3c 5b 3c 5b 3c 5b } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}