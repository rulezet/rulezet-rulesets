rule TrojanDownloader_O97M_Dotraj_G_2{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.G,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5b 72 75 6e 74 69 6d 65 2e 69 6e 74 65 72 6f 70 73 65 72 76 69 63 65 73 2e 6d 61 72 73 68 61 6c 5d 2e 67 65 74 6d 65 6d 62 65 72 73 28 29 5b 34 5d 2e 6e 61 6d 65 29 2e 69 6e 76 6f 6b 65 28 20 5b 72 75 6e 74 69 6d 65 2e 69 6e 74 65 72 6f 70 73 65 72 76 69 63 65 73 2e 6d 61 72 73 68 61 6c 5d 3a 3a 73 65 63 75 72 65 73 74 72 69 6e 67 74 6f 67 6c 71 6a } 		$a_02_1 = {20 3d 20 43 6f 73 28 90 10 08 00 20 2d 20 4f 63 74 28 90 10 08 00 20 2b 20 90 1d 09 00 20 2a 20 90 1d 09 00 20 2d 20 43 42 6f 6f 6c 28 90 1d 09 00 29 29 29 } 	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1) >=2
 
}