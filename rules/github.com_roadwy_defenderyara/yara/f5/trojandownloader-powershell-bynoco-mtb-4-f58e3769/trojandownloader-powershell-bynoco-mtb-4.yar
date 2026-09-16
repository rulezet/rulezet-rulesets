rule TrojanDownloader_PowerShell_Bynoco_MTB_4{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 2e 28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 2e 22 49 6e 76 6f 6b 65 } 		$a_01_1 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 70 77 73 79 33 73 27 2c 27 61 6e 2e 65 78 65 } 		$a_01_2 = {73 74 41 52 74 60 2d 73 6c 45 60 45 70 20 32 30 3b 20 4d 6f 76 65 2d 49 74 65 6d 20 22 61 6e 2e 65 78 65 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}