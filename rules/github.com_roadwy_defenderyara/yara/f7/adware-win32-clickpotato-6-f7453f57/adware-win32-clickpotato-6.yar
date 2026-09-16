rule Adware_Win32_ClickPotato_6{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 ?? 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 ?? ?? ?? ?? 88 16 46 3b f1 76 ef } 		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 73 2e 73 65 65 6b 6d 6f 2e 63 6f 6d } 		$a_00_2 = {65 6e 61 62 6c 65 5f 74 73 5f 6c 6f 67 67 69 6e 67 } 		$a_00_3 = {69 63 6e 61 6d 65 7c 69 63 76 65 72 73 69 6f 6e 7c 74 69 64 7c 6f 73 7c 6c 6f 63 61 6c 65 7c 62 72 6f 77 73 65 72 7c 63 73 63 69 64 7c 68 64 69 64 7c 6d 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}