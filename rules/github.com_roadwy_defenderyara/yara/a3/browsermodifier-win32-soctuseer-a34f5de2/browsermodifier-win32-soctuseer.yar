rule BrowserModifier_Win32_Soctuseer{
	meta:
		description = "BrowserModifier:Win32/Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 57 45 5f 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } 		$a_01_1 = {53 6f 63 69 61 32 53 65 61 72 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}