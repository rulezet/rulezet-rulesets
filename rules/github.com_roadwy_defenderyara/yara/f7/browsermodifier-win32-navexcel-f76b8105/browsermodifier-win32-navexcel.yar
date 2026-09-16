rule BrowserModifier_Win32_NavExcel{
	meta:
		description = "BrowserModifier:Win32/NavExcel,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 6d 6f 6e 6e 61 6d 65 2e 63 6f 6d 2f 66 69 6e 64 2e 61 73 70 3f 63 6e 3d } 		$a_01_1 = {4e 61 76 48 65 6c 70 65 72 20 46 69 6c 65 20 44 65 6c 65 74 65 20 45 72 72 6f 72 21 } 		$a_01_2 = {50 6c 65 61 73 65 20 76 69 73 69 74 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6e 61 76 65 78 63 65 6c 2e 63 6f 6d 20 66 6f 72 20 73 75 70 70 6f 72 74 20 6f 6e 20 74 68 69 73 20 69 73 73 75 65 2e } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4) >=11
 
}