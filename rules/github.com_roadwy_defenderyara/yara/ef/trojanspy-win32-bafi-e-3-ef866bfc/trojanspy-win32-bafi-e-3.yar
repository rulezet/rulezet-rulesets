rule TrojanSpy_Win32_Bafi_E_3{
	meta:
		description = "TrojanSpy:Win32/Bafi.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c6 45 fc 06 68 ?? ?? ?? ?? 8d 8d c0 fe ff ff e8 ?? ?? ?? ?? c6 45 fc 0a 68 ?? ?? ?? ?? 8d 95 c0 fe ff ff 52 8d 85 9c fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 0c 89 85 38 fe ff ff 8b 8d 38 fe ff ff 89 8d 34 fe ff ff c6 45 fc 0b 68 ?? ?? ?? ?? 8b 95 34 fe ff ff 52 } 		$a_01_1 = {0f b6 4d ff 03 c8 88 4d ff 0f b6 55 fe 83 c2 01 81 e2 0f 00 00 80 79 05 4a 83 ca f0 42 88 55 fe 8b 45 08 03 45 f0 0f b6 08 0f b6 55 ff 33 ca 8b 45 e8 8b 10 8b 45 f0 88 0c 02 8b 4d 08 03 4d f0 8a 11 88 55 ff eb 9d } 		$a_00_2 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 } 		$a_00_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 6c 6f 67 69 6e 2e 70 68 70 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}