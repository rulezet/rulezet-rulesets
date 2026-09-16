rule TrojanDownloader_Win32_Allsum{
	meta:
		description = "TrojanDownloader:Win32/Allsum,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 51 75 65 72 79 50 6c 75 67 69 6e 00 00 00 } 		$a_00_1 = {64 3a 5c 77 6f 72 6b 5c 63 66 73 32 2e 6d 65 5c 63 66 73 32 5c 73 72 63 5c 6d 61 69 6e 5c } 		$a_00_2 = {65 76 65 6e 74 61 64 63 6c 69 63 6b } 		$a_00_3 = {68 74 74 70 3a 2f 2f 00 32 30 32 2e 31 30 34 2e 31 31 2e 39 34 } 		$a_01_4 = {53 48 4f 57 20 41 44 20 50 6c 75 67 69 6e } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}