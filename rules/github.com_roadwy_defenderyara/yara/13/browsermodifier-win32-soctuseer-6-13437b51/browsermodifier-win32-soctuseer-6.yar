rule BrowserModifier_Win32_Soctuseer_6{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 00 57 00 45 00 5f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } 		$a_01_1 = {2f 00 44 00 45 00 4c 00 45 00 54 00 45 00 5f 00 4f 00 4e 00 5f 00 43 00 4c 00 4f 00 53 00 45 00 } 		$a_01_2 = {2f 00 4e 00 41 00 4d 00 45 00 20 00 53 00 6f 00 63 00 69 00 61 00 6c 00 32 00 53 00 65 00 61 00 72 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}