rule TrojanDownloader_O97M_Obfuse_RX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 22 68 74 74 70 73 3a 2f 2f 72 6f 63 6b 74 72 61 64 65 2e 61 6c 70 68 61 63 6f 64 65 2e 6d 6f 62 69 2f 75 70 6c 6f 61 64 73 2f 62 69 6e 5f 50 72 6f 74 65 63 74 65 64 2e 65 78 65 22 2c 20 46 61 6c 73 65 } 		$a_01_1 = {2b 20 22 49 47 5a 4b 47 42 49 2e 65 78 65 22 } 		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 48 45 4c 4c 2e 41 50 50 4c 49 43 41 54 49 4f 4e 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}