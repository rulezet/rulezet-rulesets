rule BrowserModifier_Win32_Adrozek_3{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 2e 00 61 00 76 00 61 00 73 00 74 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}