rule TrojanDownloader_O97M_Obfuse_BPK_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 70 2f 2e 6d 40 6a 34 38 30 39 32 33 25 31 34 38 30 39 32 33 2f 31 3a 2f 74 70 68 74 20 22 29 } 		$a_01_1 = {53 68 65 6c 6c 20 53 74 72 52 65 76 65 72 73 65 28 53 52 65 76 65 72 73 65 4d 6f 64 28 22 74 61 73 68 20 6d 2f 63 64 20 63 6d 22 29 29 } 		$a_01_2 = {53 68 65 6c 6c 20 78 6d 6f 72 67 61 6e 64 64 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}