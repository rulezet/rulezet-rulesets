rule Adware_Win32_ClickPotato{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 ?? 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 ?? ?? ?? ?? 88 16 46 3b f1 76 ef } 		$a_00_1 = {5c 5c 2e 5c 53 63 73 69 25 64 3a } 		$a_00_2 = {70 69 6e 62 61 6c 6c 63 6f 72 70 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}