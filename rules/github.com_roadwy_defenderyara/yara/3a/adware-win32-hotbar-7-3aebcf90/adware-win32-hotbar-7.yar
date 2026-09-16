rule Adware_Win32_Hotbar_7{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {56 8b 74 24 08 8b 0e 8b 01 8b 50 10 57 ff d2 83 7e 0c 00 8d 4e 0c 7c ?? 3b 06 75 ?? 8b fe b8 01 00 00 00 f0 0f c1 01 } 		$a_00_1 = {69 74 73 2e 6e 6f 74 2e 6f 6b } 		$a_00_2 = {68 74 74 70 3a 2f 2f 6f 70 65 6e 2f 3f 75 72 6c 3d } 		$a_00_3 = {73 65 65 6b 6d 6f } 		$a_00_4 = {68 6f 74 62 61 72 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}