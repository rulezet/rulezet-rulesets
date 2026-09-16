rule TrojanDownloader_Win32_Begseabug_A{
	meta:
		description = "TrojanDownloader:Win32/Begseabug.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 42 65 62 75 67 50 72 69 76 69 6c 65 67 65 } 		$a_03_1 = {63 6f 6d 3a 38 30 38 30 [0-06] 2f 73 63 2e 70 6e 67 } 		$a_01_2 = {68 2d af 9c 4e } 		$a_01_3 = {53 59 53 54 45 4d 33 32 5c 73 79 73 74 65 6d 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}