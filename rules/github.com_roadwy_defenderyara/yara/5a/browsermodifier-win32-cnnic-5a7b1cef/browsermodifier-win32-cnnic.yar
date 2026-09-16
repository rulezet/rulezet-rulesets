rule BrowserModifier_Win32_CNNIC{
	meta:
		description = "BrowserModifier:Win32/CNNIC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 70 69 65 5f 53 74 61 72 74 48 6f 6f 6b } 		$a_01_1 = {63 64 6e 73 70 69 65 2e 64 6c 6c } 		$a_01_2 = {63 64 6e 75 6e 69 6e 73 2e 65 78 65 } 		$a_01_3 = {43 64 6e 48 69 64 65 } 		$a_01_4 = {5c 63 64 6e 70 72 65 76 2e 64 61 74 } 		$a_01_5 = {5c 63 64 6e 70 72 6f 74 2e 64 61 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=10
 
}