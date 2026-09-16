rule BrowserModifier_Win32_Webalta_2{
	meta:
		description = "BrowserModifier:Win32/Webalta,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {b1 2e 83 f8 04 7e 0b 38 4c 18 fc 75 05 c6 44 18 fc 00 83 f8 05 7e 0b 38 4c 18 fb 75 05 c6 44 18 fb 00 83 f8 08 7e 0b 38 4c 18 f9 75 05 c6 44 18 f9 00 83 f8 09 } 		$a_01_1 = {47 6c 6f 62 61 6c 5c 53 65 61 72 63 68 53 65 72 76 69 63 65 } 		$a_01_2 = {57 65 62 61 6c 74 61 53 65 72 76 69 63 65 } 		$a_00_3 = {77 65 62 61 6c 74 61 2e 72 75 2f 73 72 63 68 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}