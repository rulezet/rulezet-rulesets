rule BrowserModifier_Win32_OneStepSearch{
	meta:
		description = "BrowserModifier:Win32/OneStepSearch,SIGNATURE_TYPE_PEHSTR_EXT,38 00 33 00 04 00 00 "
		
	strings :
		$a_00_0 = {c0 e0 02 8b d5 c1 fa 04 0a d0 } 		$a_03_1 = {63 68 65 63 6b 75 70 64 [0-04] 73 6c 6f 61 64 [0-04] 74 62 68 69 64 65 [0-04] 74 62 73 68 6f 77 } 		$a_11_2 = {6e 65 53 74 65 70 53 65 61 72 63 68 2e 2e 2e 00 01 } 		$a_4f_3 = {65 53 74 65 70 2e 2e 2e 00 00 00 78 70 00 00 02 00 } 	condition:
		((#a_00_0  & 1)*50+(#a_03_1  & 1)*5+(#a_11_2  & 1)*1+(#a_4f_3  & 1)*2816) >=51
 
}