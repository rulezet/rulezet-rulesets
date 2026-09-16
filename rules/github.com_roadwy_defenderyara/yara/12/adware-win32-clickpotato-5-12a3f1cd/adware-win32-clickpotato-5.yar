rule Adware_Win32_ClickPotato_5{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 50 69 6e 62 61 6c 6c 43 6f 72 70 2d 42 53 41 49 2f 56 45 52 5f 53 54 52 5f 43 4f 4d 4d 41 } 		$a_03_1 = {8d 34 01 3b f7 7e 90 14 8b 4d 08 a1 ?? ?? ?? ?? 03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 18 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 ?? ?? ?? ?? 88 16 46 3b f1 76 ef } 		$a_03_2 = {63 61 6c 44 72 69 76 65 00 00 00 00 50 68 79 73 69 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 43 53 49 44 49 53 4b 00 00 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}