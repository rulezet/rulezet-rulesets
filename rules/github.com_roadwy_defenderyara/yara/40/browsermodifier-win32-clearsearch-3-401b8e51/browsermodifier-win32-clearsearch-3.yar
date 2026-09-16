rule BrowserModifier_Win32_ClearSearch_3{
	meta:
		description = "BrowserModifier:Win32/ClearSearch,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 61 69 74 5f 46 6f 72 5f 4f 6e 6c 69 6e 65 } 		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 72 53 63 68 } 		$a_00_2 = {70 72 6f 6d 6f 3d 25 64 } 		$a_01_3 = {42 49 20 69 6e 73 74 61 6c 6c 65 72 } 		$a_01_4 = {68 74 74 70 3a 2f 2f 73 64 73 2e 63 6c 72 73 63 68 2e 63 6f 6d 2f } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}