rule TrojanDownloader_O97M_Obfuse_BPK_MTB_23{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 63 61 6c 63 73 65 78 6b 6f 6f 6b 6b } 		$a_01_1 = {3d 20 22 74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f 22 } 		$a_01_2 = {3d 20 63 61 6c 63 73 65 63 79 6b 6f 39 5f 31 32 20 2b 20 63 61 6c 63 73 65 63 79 6b 6f 39 5f 34 32 5f 61 73 20 2b 20 6b 39 5f 34 32 5f 61 73 } 		$a_01_3 = {3d 20 63 61 6c 63 73 65 78 6b 6f 20 2b 20 63 61 6c 63 73 65 63 79 6b 6f 6f 30 5f 53 44 5f 31 32 20 2b 20 70 69 6e 67 5f 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}