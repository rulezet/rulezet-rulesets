rule Adware_Win32_Hotbar_9{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 6f 77 6e 6c 6f 61 64 73 31 2e 7a 61 6e 67 6f 2e 63 6f 6d } 		$a_00_1 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 61 6e 63 65 6c 20 74 68 65 20 64 6f 77 6e 6c 6f 61 64 3f } 		$a_03_2 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 ?? 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 ?? ?? ?? ?? 88 16 46 3b f1 76 ef } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}