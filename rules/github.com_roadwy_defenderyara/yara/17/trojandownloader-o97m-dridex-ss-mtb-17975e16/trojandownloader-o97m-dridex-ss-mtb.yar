rule TrojanDownloader_O97M_Dridex_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 4d 53 58 4d 4c 4b 73 71 25 70 2c 32 2e 58 4d 4c 48 54 54 50 22 2c 20 22 4b 73 71 25 70 2c 22 2c 20 22 22 29 } 		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 72 75 6e 67 4a 49 70 67 5f 58 64 67 4a 49 70 67 5f 58 6c 6c 33 32 2e 65 78 67 } 		$a_01_2 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 } 		$a_01_3 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}