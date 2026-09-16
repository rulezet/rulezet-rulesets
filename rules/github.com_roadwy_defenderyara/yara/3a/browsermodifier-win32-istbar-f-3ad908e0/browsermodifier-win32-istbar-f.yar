rule BrowserModifier_Win32_Istbar_F{
	meta:
		description = "BrowserModifier:Win32/Istbar.F,SIGNATURE_TYPE_PEHSTR_EXT,17 00 14 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6c 6f 74 63 68 2e 63 6f 6d 2f 69 73 74 2f 73 6f 66 74 77 61 72 65 73 2f 76 34 2e 30 2f 69 73 74 64 6f 77 6e 6c 6f 61 64 2e 65 78 65 } 		$a_00_1 = {00 49 53 54 00 } 		$a_02_2 = {61 69 64 3a 90 05 07 03 30 2d 39 20 2f 63 66 67 3a } 		$a_00_3 = {35 34 36 33 33 33 73 64 66 67 73 64 66 67 66 67 64 66 73 67 73 64 66 67 73 64 66 67 36 } 	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=20
 
}