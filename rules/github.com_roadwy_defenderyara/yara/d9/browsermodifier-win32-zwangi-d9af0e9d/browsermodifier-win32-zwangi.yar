rule BrowserModifier_Win32_Zwangi{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 26 74 0a 3c 3d 74 06 } 		$a_01_1 = {8b 55 ec 3b 55 f4 74 6a 8b 45 fc 83 c0 01 25 ff 00 00 00 89 45 fc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}