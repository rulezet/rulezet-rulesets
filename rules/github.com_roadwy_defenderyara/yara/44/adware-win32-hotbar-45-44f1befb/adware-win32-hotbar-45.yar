rule Adware_Win32_Hotbar_45{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 6e 00 74 00 6e 00 74 00 43 00 6e 00 74 00 72 00 2e 00 43 00 6e 00 74 00 6e 00 74 00 44 00 69 00 73 00 70 00 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 68 6f 74 62 61 72 2e 63 6f 6d } 		$a_01_2 = {6a 61 76 61 73 63 72 69 70 74 3a 77 69 6e 64 6f 77 2e 6f 70 65 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}