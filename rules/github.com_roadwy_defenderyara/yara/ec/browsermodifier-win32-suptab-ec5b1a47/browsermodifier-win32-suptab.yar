rule BrowserModifier_Win32_SupTab{
	meta:
		description = "BrowserModifier:Win32/SupTab,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 4f 75 72 73 75 72 66 69 6e 67 2e 65 78 65 20 2d 73 69 6c 65 6e 63 65 20 2d 70 74 69 64 3d } 		$a_01_1 = {26 62 75 6e 64 6c 65 3d 43 6f 6d 70 6f 6e 65 6e 74 26 70 72 6f 64 75 63 74 3d 4f 75 72 73 75 72 66 69 6e 67 26 73 74 61 74 75 73 3d } 		$a_01_2 = {5c 6c 75 63 6b 79 73 65 61 72 63 68 65 73 53 6f 66 74 77 61 72 65 5c 6c 75 63 6b 79 73 65 61 72 63 68 65 73 68 70 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}