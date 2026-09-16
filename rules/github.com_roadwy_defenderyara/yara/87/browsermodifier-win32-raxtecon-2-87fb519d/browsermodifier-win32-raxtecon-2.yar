rule BrowserModifier_Win32_Raxtecon_2{
	meta:
		description = "BrowserModifier:Win32/Raxtecon,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 65 62 20 43 6f 6e 74 65 6e 74 20 42 6c 6f 63 6b 65 64 20 62 79 20 43 6f 6e 74 65 6e 74 20 44 65 66 65 6e 64 65 72 } 		$a_01_1 = {43 6f 6e 44 65 66 53 65 74 75 70 2e 65 78 65 } 		$a_01_2 = {63 6f 6e 74 65 6e 74 64 65 66 65 6e 64 65 72 64 72 76 2e 73 79 73 } 		$a_03_3 = {68 74 74 70 3a 2f 2f 63 6f 6e 74 65 6e 74 64 65 66 65 6e 64 65 72 2d 90 1d 05 00 2e 6f 72 67 2f 76 65 72 73 69 6f 6e 2f 63 68 65 63 6b 6e 65 77 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}