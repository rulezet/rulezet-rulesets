rule BrowserModifier_Win32_ClearSearch{
	meta:
		description = "BrowserModifier:Win32/ClearSearch,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6c 72 53 72 63 68 5f 43 6f 6e 6e 65 63 74 } 		$a_01_1 = {63 73 41 4f 4c 6c 64 72 } 		$a_01_2 = {49 6e 69 74 49 6e 73 74 61 6e 63 65 } 		$a_01_3 = {54 65 72 6d 49 6e 73 74 61 6e 63 65 } 		$a_01_4 = {43 6c 72 53 72 63 68 5f 44 69 73 63 6f 6e 6e 65 63 74 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4) >=9
 
}