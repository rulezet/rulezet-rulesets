rule BrowserModifier_Win32_Raxtecon{
	meta:
		description = "BrowserModifier:Win32/Raxtecon,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 63 6f 6e 64 65 66 73 65 74 75 70 2e 6c 6f 67 } 		$a_01_1 = {5c 43 6f 6e 74 65 6e 74 20 44 65 66 65 6e 64 65 72 } 		$a_01_2 = {5c 63 6f 6e 64 65 66 72 6d 2e 62 61 74 } 		$a_01_3 = {43 6f 6e 74 65 6e 74 44 65 66 65 6e 64 65 72 5c 52 65 6c 65 61 73 65 5c 63 6f 6e 64 65 66 63 6c 65 61 6e 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}