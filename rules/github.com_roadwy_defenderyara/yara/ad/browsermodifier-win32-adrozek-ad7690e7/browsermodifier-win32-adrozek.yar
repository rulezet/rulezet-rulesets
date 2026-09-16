rule BrowserModifier_Win32_Adrozek{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {84 d2 75 33 80 39 4c 75 2e 80 79 01 6f 75 28 80 fb 78 75 23 80 79 0d 41 75 1d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}