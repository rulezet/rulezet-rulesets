rule TrojanDownloader_Win32_Banload_DUN{
	meta:
		description = "TrojanDownloader:Win32/Banload.DUN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 } 		$a_00_1 = {2e 74 78 74 } 		$a_00_2 = {2a 2e 6d 62 6f 78 } 		$a_00_3 = {2a 2e 77 61 62 } 		$a_00_4 = {2a 2e 6d 62 78 } 		$a_00_5 = {2a 2e 65 6d 6c } 		$a_00_6 = {2a 2e 74 62 62 } 		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_02_8 = {33 ff 8d 45 e0 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 fc e8 ?? ?? fe ff 8b 4d e0 8d 45 e4 ba ?? ?? 41 00 e8 ?? ?? fe ff 8b 45 e4 e8 ?? ?? fe ff 89 45 f0 be 03 00 00 00 8d 45 d8 50 b9 02 00 00 00 8b d6 8b 45 fc } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1) >=9
 
}