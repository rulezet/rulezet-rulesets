rule TrojanDownloader_O97M_Obfuse_BPK_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 20 68 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 74 22 } 		$a_01_1 = {59 61 68 6f 6f 64 69 31 31 31 31 20 3d 20 70 64 61 73 31 20 2b 20 6b 6f 32 20 2b 20 6b 6f 32 33 20 2b 20 6f 6b 33 } 		$a_01_2 = {59 61 68 6f 6f 64 69 2e 53 54 41 52 54 4f 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}