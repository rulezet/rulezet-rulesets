rule TrojanDownloader_PowerShell_Bynoco_MTB{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 65 72 73 68 65 6c 6c 20 22 20 26 20 22 28 4e 45 77 2d 6f 62 6a 45 22 20 26 20 6c 6c 6c 20 26 20 22 74 20 22 20 26 20 22 73 79 73 74 65 6d 2e 6e 65 74 2e 77 45 42 63 6c 49 65 6e 54 29 2e 44 6f 77 6e 4c 6f 41 64 66 49 6c 45 } 		$a_01_1 = {68 74 74 70 73 3a 2f 2f 63 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 37 35 32 69 32 72 7a 7a 31 2e 6a 70 67 } 		$a_01_2 = {45 4e 76 3a 54 45 4d 50 5c 76 68 66 2e 76 62 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}