rule TrojanDownloader_O97M_Obfuse_BPK_MTB_30{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 73 3a 2f 2f 25 34 30 25 34 30 40 6a 2e 6d 70 2f 61 37 73 38 64 61 73 67 64 68 73 61 73 61 64 66 78 63 22 } 		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 68 69 72 65 6d 65 29 2e 45 78 65 63 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 31 30 20 2b 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e 31 31 } 		$a_01_2 = {3d 20 22 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 61 73 64 61 78 61 73 78 64 61 73 61 73 64 64 6b 61 6f 73 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}