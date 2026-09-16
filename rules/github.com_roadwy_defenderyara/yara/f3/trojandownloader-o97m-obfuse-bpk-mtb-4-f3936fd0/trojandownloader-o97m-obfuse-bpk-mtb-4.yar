rule TrojanDownloader_O97M_Obfuse_BPK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 72 61 32 20 3d 20 4e 61 6d 61 6b 42 6f 72 61 20 2b 20 6c 6f 72 61 } 		$a_01_1 = {3d 20 22 20 68 74 74 70 73 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 62 69 74 6c 79 2e 63 6f 6d 2f 61 77 6b 64 68 69 6b 68 61 73 64 22 } 		$a_01_2 = {52 75 6e 20 6c 6f 72 61 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}