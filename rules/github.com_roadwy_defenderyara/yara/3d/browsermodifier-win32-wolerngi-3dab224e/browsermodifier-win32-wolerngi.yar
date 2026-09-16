rule BrowserModifier_Win32_Wolerngi{
	meta:
		description = "BrowserModifier:Win32/Wolerngi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 53 5f 43 68 65 63 6b 55 70 64 61 74 65 } 		$a_01_1 = {47 53 5f 52 75 6c 65 4c 69 73 74 } 		$a_01_2 = {5b 4e 5d 20 50 72 6f 64 75 63 74 4b 65 79 20 3a } 		$a_01_3 = {67 65 6e 63 6f 6c 61 62 73 6c 6c 63 2e 63 6f 6d 2f 73 65 72 76 69 63 65 73 2f 75 70 64 61 74 65 2e 70 68 70 3f 61 66 66 69 64 3d } 		$a_01_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 47 53 61 66 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}