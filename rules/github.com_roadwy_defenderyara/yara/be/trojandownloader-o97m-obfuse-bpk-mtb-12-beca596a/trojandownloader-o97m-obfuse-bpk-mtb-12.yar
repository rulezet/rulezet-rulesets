rule TrojanDownloader_O97M_Obfuse_BPK_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 42 41 2e 53 68 65 6c 6c 28 4b 43 4b 52 30 68 4a 69 50 20 2b 20 69 4a 6c 50 76 73 6c 6e 70 20 2b 20 73 6d 59 31 44 63 64 66 6c 20 2b 20 58 67 64 6c 49 68 4f 57 59 29 29 } 		$a_01_1 = {3d 20 41 70 77 41 36 46 62 47 58 20 26 20 53 74 72 52 65 76 65 72 73 65 28 4d 69 64 28 77 6c 61 52 71 67 4c 61 77 2c 20 47 37 43 76 64 46 73 4c 6a 2c 20 32 29 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}