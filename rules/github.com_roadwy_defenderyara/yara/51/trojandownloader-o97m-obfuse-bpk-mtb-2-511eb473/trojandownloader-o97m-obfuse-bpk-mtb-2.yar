rule TrojanDownloader_O97M_Obfuse_BPK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 20 3d 20 22 68 74 74 70 3a 2f 2f 34 47 50 2e 4d 45 2f 62 6c 74 63 2f 31 35 39 30 30 37 34 35 39 36 35 32 31 2e 74 78 74 22 } 		$a_01_1 = {3d 20 57 69 6e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 6d 73 68 74 61 20 22 20 26 20 7a 2c 20 30 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}