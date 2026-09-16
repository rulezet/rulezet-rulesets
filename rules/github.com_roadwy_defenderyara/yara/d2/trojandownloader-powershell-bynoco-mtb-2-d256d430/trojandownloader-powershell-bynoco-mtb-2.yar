rule TrojanDownloader_PowerShell_Bynoco_MTB_2{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 78 48 74 74 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } 		$a_01_1 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 37 32 2e 31 36 2e 37 30 2e 31 30 2f 70 73 31 5f 62 36 34 2e 63 72 74 22 2c 20 46 61 6c 73 65 } 		$a_01_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 65 6e 63 6f 64 65 64 5f 70 73 31 2e 63 72 74 22 } 		$a_01_3 = {53 68 65 6c 6c 20 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}