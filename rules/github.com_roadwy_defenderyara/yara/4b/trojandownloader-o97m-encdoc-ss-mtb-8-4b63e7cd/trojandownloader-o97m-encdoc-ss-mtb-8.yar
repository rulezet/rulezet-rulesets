rule TrojanDownloader_O97M_EncDoc_SS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 56 64 31 41 55 52 32 65 57 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 68 47 46 79 73 47 46 29 } 		$a_03_1 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 6a 7c 71 7c 55 7c 76 7c 4d 7c 4f 7c 58 7c 7a 7c 44 7c 48 7c 5a 7c 56 7c 50 7c 51 7c 59 7c 49 7c 4e 7c 77 7c 4b 7c 4c 22 [0-07] 2e 47 6c 6f 62 61 6c 20 3d 20 54 72 75 65 [0-07] 45 6e 64 20 57 69 74 68 } 		$a_01_2 = {59 59 49 6d 79 63 4d 67 20 3d 20 56 64 31 41 55 52 32 65 57 2e 52 65 70 6c 61 63 65 28 42 32 58 6b 4b 6b 55 70 68 28 30 29 2c 20 22 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}