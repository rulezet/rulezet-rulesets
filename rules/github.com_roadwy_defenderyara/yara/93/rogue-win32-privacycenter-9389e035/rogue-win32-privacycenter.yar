rule Rogue_Win32_PrivacyCenter{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 70 61 72 73 65 49 6e 74 } 		$a_03_1 = {ba 86 01 00 00 e8 ?? ?? ?? ?? 8b c3 ba 78 01 00 00 } 		$a_03_2 = {ba 76 02 00 00 8b c3 e8 ?? ?? ?? ?? ba 5f 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}