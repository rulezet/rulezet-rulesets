rule TrojanDownloader_O97M_Obfuse_BPK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 6a 2e 6d 70 2f [0-28] 22 } 		$a_01_1 = {3a 20 53 68 65 6c 6c 20 28 22 70 69 6e 67 2e 65 78 65 22 29 } 		$a_01_2 = {4d 73 67 42 6f 78 20 28 22 45 72 72 6f 72 21 22 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}