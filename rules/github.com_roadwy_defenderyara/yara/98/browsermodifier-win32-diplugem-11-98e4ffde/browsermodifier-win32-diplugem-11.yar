rule BrowserModifier_Win32_Diplugem_11{
	meta:
		description = "BrowserModifier:Win32/Diplugem,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_13_0 = {00 00 00 00 b9 0a 02 00 00 8d 54 24 90 01 01 8b 35 90 01 04 89 b4 24 90 01 02 00 00 89 14 24 c7 44 24 04 00 00 00 00 c7 44 24 08 0a 02 00 00 89 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 b9 04 01 00 00 8d 54 24 90 01 01 89 14 24 c7 44 24 04 04 01 00 00 89 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 0f b7 4c 24 90 01 01 0f b7 54 24 90 00 01 } 		$a_b8_1 = {00 00 00 8b 8c 24 90 01 02 00 00 89 c2 29 ca 89 c1 81 e9 } 	condition:
		((#a_13_0  & 1)*10+(#a_b8_1  & 1)*13056) >=11
 
}