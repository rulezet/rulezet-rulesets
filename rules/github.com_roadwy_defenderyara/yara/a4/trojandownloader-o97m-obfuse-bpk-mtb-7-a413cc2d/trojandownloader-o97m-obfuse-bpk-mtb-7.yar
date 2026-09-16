rule TrojanDownloader_O97M_Obfuse_BPK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 41 61 59 79 4a 61 30 20 2b 20 41 61 59 79 4a 61 31 20 2b 20 41 61 59 79 4a 61 32 20 2b 20 41 61 59 79 4a 61 33 } 		$a_01_1 = {3d 20 64 73 73 65 45 52 44 59 20 26 20 43 68 72 28 41 61 59 79 4a 61 28 41 64 59 44 4a 61 29 29 } 		$a_01_2 = {53 68 65 6c 6c 20 28 41 61 59 79 4a 61 35 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}