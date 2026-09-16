rule TrojanDownloader_O97M_Obfuse_BPK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2f 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 40 6a 2e 6d 70 5c 6b 61 73 64 61 73 6a 78 69 61 6b 73 64 64 6b 61 64 73 64 73 6b 64 64 22 } 		$a_01_1 = {3d 20 53 68 65 6c 6c 28 61 73 69 64 6d 61 69 73 6d 61 20 2b 20 50 73 69 64 6d 50 69 73 6d 50 2c 20 76 62 4d 69 6e 69 6d 69 7a 65 64 46 6f 63 75 73 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}