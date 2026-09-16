rule BrowserModifier_Win32_Soctuseer_2{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 69 6e 73 74 61 6c 6c 2d 61 70 70 73 2e 63 6f 6d 2f 73 32 73 5f 69 6e 73 74 61 6c 6c 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}