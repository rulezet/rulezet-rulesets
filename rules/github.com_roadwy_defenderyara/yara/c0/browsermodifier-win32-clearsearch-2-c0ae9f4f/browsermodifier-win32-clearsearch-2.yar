rule BrowserModifier_Win32_ClearSearch_2{
	meta:
		description = "BrowserModifier:Win32/ClearSearch,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 63 73 69 65 5f 75 73 62 5f 63 61 6d 70 61 69 67 6e 73 2e } 		$a_01_1 = {53 74 61 72 74 69 6e 67 20 55 52 4c 53 69 64 65 42 61 72 20 50 72 6f 63 65 73 73 } 		$a_01_2 = {55 53 42 20 4d 61 74 63 68 } 		$a_01_3 = {63 3a 5c 63 73 69 65 5f 64 65 62 75 67 2e 74 78 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=12
 
}