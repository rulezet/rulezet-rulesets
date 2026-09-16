rule BrowserModifier_Win32_iLookup_2{
	meta:
		description = "BrowserModifier:Win32/iLookup,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6d 2f 74 6f 6f 6c 62 61 72 2f 62 61 72 2f } 		$a_01_1 = {69 6e 65 62 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } 		$a_01_2 = {42 72 6f 61 64 63 61 73 74 53 79 73 74 65 6d 4d 65 73 73 61 67 65 } 		$a_01_3 = {70 6f 70 75 70 5f 65 6e 61 62 6c 65 64 } 		$a_01_4 = {25 73 25 73 26 76 69 64 3d 25 6c 75 26 63 63 6f 64 3d 25 6c 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}