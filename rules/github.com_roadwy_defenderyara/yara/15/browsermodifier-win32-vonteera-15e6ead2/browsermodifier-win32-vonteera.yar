rule BrowserModifier_Win32_Vonteera{
	meta:
		description = "BrowserModifier:Win32/Vonteera,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 85 a0 fd ff ff 50 68 04 01 00 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 a0 fd ff ff 68 22 01 00 00 50 e8 ?? ?? ?? ?? 68 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}