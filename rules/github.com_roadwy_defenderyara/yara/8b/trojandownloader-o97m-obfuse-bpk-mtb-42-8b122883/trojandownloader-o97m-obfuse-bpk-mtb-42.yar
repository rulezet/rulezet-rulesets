rule TrojanDownloader_O97M_Obfuse_BPK_MTB_42{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 6f 6b 6f 64 5f 78 77 6b 6f 6b 61 73 64 5f 57 64 6f 20 2b 20 61 53 44 4b 4b 5f 64 6d 77 6f 20 2b 20 6b 6f 6b 5f 64 61 6b 73 64 6f 20 2b 20 61 73 6b 64 6f 5f 57 78 6d 6f 20 2b 20 6b 6f 5f 64 77 6b 6f } 		$a_01_1 = {3d 20 6c 6f 6c 6f 20 2b 20 6b 6f 6b 6f 20 2b 20 70 6c 70 6c 20 2b 20 70 6c 77 6f 20 2b 20 6c 61 64 70 73 6f 20 2b 20 68 75 70 70 70 20 2b 20 6b 6f 6b 6f 77 6f 6b 20 2b 20 6b 6f 6c 64 69 63 20 2b 20 70 75 74 6f 20 2b 20 6b 6f 6c 69 63 6c 63 20 2b 20 6b 6f 6c 69 63 6c 63 } 		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 61 6c 69 29 2e 45 58 45 43 20 6c 6c 6c 20 2b 20 6c 6f 30 6f 6c } 		$a_01_3 = {41 55 74 6f 5f 43 6c 4f 73 45 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}