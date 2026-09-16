rule BrowserModifier_Win32_Zwangi_2{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {46 80 3e 20 74 fa 80 3e 22 75 08 b9 22 00 00 00 46 eb 05 b9 20 00 00 00 8b de } 		$a_01_1 = {5a 75 6d 69 65 20 6c 6f 61 64 65 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}