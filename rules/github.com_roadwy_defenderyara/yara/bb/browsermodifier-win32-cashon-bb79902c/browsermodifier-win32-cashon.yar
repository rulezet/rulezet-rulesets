rule BrowserModifier_Win32_CashOn{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 72 65 76 69 6f 75 73 5f 75 70 64 61 74 65 5f 65 78 65 } 		$a_01_1 = {43 61 73 68 4f 6e 5c 62 69 6e 00 00 2a 2e 65 78 65 00 00 00 55 50 44 41 54 45 52 00 45 6e 61 62 6c 65 20 42 72 6f 77 73 65 72 20 45 78 74 65 6e 73 69 6f 6e 73 } 		$a_01_2 = {6e 63 73 65 72 76 2a 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2) >=8
 
}