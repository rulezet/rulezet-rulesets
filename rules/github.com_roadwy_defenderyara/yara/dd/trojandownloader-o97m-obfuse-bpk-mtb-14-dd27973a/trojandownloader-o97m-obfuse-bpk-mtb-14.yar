rule TrojanDownloader_O97M_Obfuse_BPK_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 6a 2e 6d 70 2f 77 61 73 61 6a 73 69 64 6a 61 73 64 61 73 64 6b 6f 6f 63 73 22 } 		$a_01_1 = {3d 20 63 61 6c 63 20 2b 20 63 61 6c 63 31 20 2b 20 63 61 6c 63 32 20 2b 20 63 61 6c 63 33 20 2b 20 63 61 6c 63 34 20 2b 20 63 61 6c 63 35 } 		$a_01_2 = {53 68 65 6c 6c 20 63 61 6c 63 6d 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}