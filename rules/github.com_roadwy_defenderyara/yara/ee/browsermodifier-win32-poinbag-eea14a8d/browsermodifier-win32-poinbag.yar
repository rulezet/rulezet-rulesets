rule BrowserModifier_Win32_PoinBag{
	meta:
		description = "BrowserModifier:Win32/PoinBag,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 69 6e 62 61 67 2e 64 6c 6c } 		$a_01_1 = {63 68 65 63 6b 5f 63 6f 75 6e 74 65 72 2e 70 68 70 3f 70 69 64 3d 70 6f 69 6e 74 62 61 67 26 6d 61 63 3d } 		$a_01_2 = {43 6f 6d 70 61 72 69 73 6f 6e 5f 70 6f 69 6e 74 62 61 67 2e 64 6c 6c } 		$a_01_3 = {70 6f 69 6e 74 62 61 67 5f 73 68 6f 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}