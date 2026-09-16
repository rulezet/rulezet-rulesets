rule TrojanDownloader_PowerShell_Bynoco_MTB_3{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 50 6f 77 65 72 53 68 65 6c 6c 20 2d 6e 6f 6c 6f 67 6f 20 2d 6e 6f 6e 69 6e 74 65 72 61 63 74 69 76 65 20 2d 77 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 } 		$a_01_1 = {28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 } 		$a_01_2 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 27 2c 27 65 72 2e 6f 72 67 2f 32 6f 76 41 39 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}