rule BrowserModifier_Win32_ClientMan{
	meta:
		description = "BrowserModifier:Win32/ClientMan,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 57 61 6c 74 5c 6d 65 74 61 48 65 6c 70 65 72 5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } 		$a_01_1 = {6d 65 74 61 77 72 64 73 2e 6c 73 74 } 		$a_01_2 = {2f 67 61 56 32 2e 70 68 70 3f 76 65 72 3d } 		$a_01_3 = {65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=6
 
}