rule TrojanDownloader_O97M_Obfuse_BPK_MTB_28{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 4c 41 53 31 5f 71 77 69 } 		$a_01_1 = {3d 20 22 74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f 22 } 		$a_01_2 = {3d 20 6b 5f 44 61 6b 6f 30 5f 77 6b 6f 6b 64 31 5f 41 20 2b 20 6b 5f 44 61 6b 6f 30 5f 44 41 4c 53 44 5f 31 32 } 		$a_01_3 = {3d 20 6f 73 64 61 73 6f 6c 78 73 6b 6f 69 65 5f 41 73 6a 64 6f 32 33 5f 61 73 64 20 2b 20 6b 5f 44 61 6b 6f 30 5f 53 44 5f 31 32 20 2b 20 6b 5f 44 61 6b 6f 30 5f 77 6b 6f 6b 64 31 5f 41 64 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}