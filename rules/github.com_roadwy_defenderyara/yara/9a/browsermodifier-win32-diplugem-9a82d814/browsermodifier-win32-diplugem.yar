rule BrowserModifier_Win32_Diplugem{
	meta:
		description = "BrowserModifier:Win32/Diplugem,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {47 6f 6f 67 6c 65 55 70 64 61 74 65 48 65 6c 70 65 72 2e 64 6c 6c 00 } 		$a_03_1 = {74 02 eb 35 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 02 eb 27 c7 45 fc 00 00 00 00 eb 09 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}