rule Adware_Win32_ClickPotato_16{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 02 33 c0 8d 74 46 02 3b f3 72 b4 89 7d f4 85 ff 0f 8e 41 01 00 00 8b 5d 08 8b 0b 8b 41 f4 8b f0 2b f7 89 45 fc 89 75 ec 3b f0 7e 02 8b c6 85 c0 79 0a 68 57 00 07 80 e8 } 		$a_01_1 = {4e 50 5f 47 65 74 45 6e 74 72 79 50 6f 69 6e 74 73 00 4e 50 5f 49 6e 69 } 		$a_01_2 = {50 00 69 00 6e 00 62 00 61 00 6c 00 6c 00 20 00 43 00 6f 00 72 00 70 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}