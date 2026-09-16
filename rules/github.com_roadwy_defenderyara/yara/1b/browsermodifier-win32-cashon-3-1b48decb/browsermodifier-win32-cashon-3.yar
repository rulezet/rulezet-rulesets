rule BrowserModifier_Win32_CashOn_3{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 50 72 6f 6a 65 63 74 5c 50 72 65 73 73 5c 70 72 65 6d 69 65 72 65 2e 6f 72 2e 6b 72 5c 53 6f 75 72 63 65 5c 50 53 43 49 6e 66 6f 2e 64 6c 6c 5f 32 30 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 73 6d 61 72 74 2e 6c 69 6e 6b 70 72 69 63 65 2e 63 6f 6d 2f 73 65 6d 2f 6f 76 65 72 74 75 72 65 5f 73 70 6f 6e 73 6f 72 5f 73 65 61 72 63 68 2e 70 68 70 3f 6d 61 78 63 6e 74 3d 26 6a 73 3d 32 26 74 79 70 65 3d } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}