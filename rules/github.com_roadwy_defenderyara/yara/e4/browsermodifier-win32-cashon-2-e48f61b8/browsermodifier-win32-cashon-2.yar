rule BrowserModifier_Win32_CashOn_2{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 43 61 73 68 4f 6e } 		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 61 73 68 4f 6e 5c 64 61 74 61 5c 70 6f 70 75 70 2e 64 61 74 } 		$a_01_2 = {23 63 61 73 68 6f 6e 5f 72 74 } 		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 43 61 73 68 4f 6e 5c } 		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 61 73 68 6f 6e 2e 63 6f 2e 6b 72 2f 73 65 61 72 63 68 2f 73 65 61 72 63 68 2e 70 68 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3) >=8
 
}