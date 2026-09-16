rule TrojanDownloader_O97M_EncDoc_RVH_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 28 22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 45 44 66 50 35 29 } 		$a_01_1 = {2e 53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 68 61 72 61 63 74 65 72 73 2e 54 65 78 74 } 		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 4e 41 4d 45 4d 45 2e 48 41 66 77 47 28 29 2c 20 54 65 43 42 45 28 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 4a 47 46 4d 28 29 2c 20 6a 69 62 4e 59 28 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 30 29 } 		$a_01_3 = {22 70 22 20 2b 20 45 44 66 50 36 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}