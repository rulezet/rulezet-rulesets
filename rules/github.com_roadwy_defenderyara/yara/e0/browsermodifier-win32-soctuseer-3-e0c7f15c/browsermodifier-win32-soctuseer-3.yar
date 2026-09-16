rule BrowserModifier_Win32_Soctuseer_3{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 42 45 5f 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } 		$a_01_1 = {53 6f 63 69 61 6c 32 53 65 20 42 72 6f 77 73 65 72 20 45 6e 68 61 6e 63 65 72 } 		$a_01_2 = {53 6f 63 69 61 32 53 65 61 72 20 42 72 6f 77 73 65 72 20 45 6e 68 61 6e 63 65 72 } 	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=51
 
}