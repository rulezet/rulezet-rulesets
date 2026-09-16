rule Adware_Win32_Hotbar_13{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 17 57 8b fa 2b f8 0f be 14 37 8a 92 ?? ?? ?? ?? 88 16 46 3b f1 76 ef 5f } 		$a_01_1 = {2f 53 69 6c 65 6e 74 20 2f 57 65 6c 63 6f 6d 65 3d 66 61 6c 73 65 20 2f 41 66 66 69 6c 69 61 74 65 49 64 3d 24 } 		$a_01_2 = {70 69 6e 62 61 6c 6c 70 75 62 6c 69 73 68 65 72 6e 65 74 77 6f 72 6b 2e 63 6f 6d 00 } 		$a_01_3 = {69 63 73 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f 53 6f 66 74 77 61 72 65 2f } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}