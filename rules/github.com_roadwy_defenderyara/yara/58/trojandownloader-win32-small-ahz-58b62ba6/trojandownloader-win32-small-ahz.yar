rule TrojanDownloader_Win32_Small_AHZ{
	meta:
		description = "TrojanDownloader:Win32/Small.AHZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 57 35 6d 62 33 4e 68 63 47 6b 75 5a 47 78 73 } 		$a_01_1 = {55 48 4a 76 5a 33 4a 68 62 55 5a 70 62 47 56 7a } 		$a_01_2 = {53 57 35 30 5a 58 4a 75 5a 58 51 67 52 58 68 77 62 47 39 79 5a 58 4a 2c } 		$a_01_3 = {49 69 42 48 54 31 52 50 49 45 52 46 54 45 46 51 55 43 42 46 54 46 4e 46 49 45 64 50 56 45 38 67 52 45 56 4d 51 6b 46 55 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}