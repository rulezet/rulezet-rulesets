rule Adware_Win32_Hotbar_4{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 14 37 8a 92 ?? ?? ?? ?? 88 16 46 3b f1 76 ef } 		$a_01_1 = {26 62 6e 61 6d 65 3d 26 62 76 65 72 3d 26 76 65 72 3d 26 6d 74 3d 30 30 55 4e 4b 4e 4f 57 4e } 		$a_01_2 = {7c 63 73 63 69 64 7c 68 64 69 64 7c 6d 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}