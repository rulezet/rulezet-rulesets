rule BrowserModifier_Win32_Prifou{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 63 46 6f 75 6e 74 61 69 6e } 		$a_01_1 = {50 72 69 63 65 20 46 6f 75 6e 74 61 69 6e } 		$a_01_2 = {66 78 61 63 78 71 36 38 0d 6f 71 71 00 } 		$a_01_3 = {59 61 78 72 70 78 57 6a 71 78 46 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}