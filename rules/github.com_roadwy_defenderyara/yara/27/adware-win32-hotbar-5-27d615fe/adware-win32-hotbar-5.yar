rule Adware_Win32_Hotbar_5{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 62 48 6f 73 74 4f 45 2e 44 4c 4c 00 } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 48 6f 74 62 61 72 5c 48 6f 74 62 61 72 5c 00 49 6e 73 74 61 6c 6c 00 48 6f 74 62 61 72 } 		$a_01_2 = {52 65 67 69 73 74 65 72 52 65 62 61 72 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}