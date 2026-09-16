rule TrojanDownloader_O97M_Obfuse_BPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 52 52 4f 52 20 21 21 21 22 3a 20 43 61 6c 6c 20 53 68 65 6c 6c 20 5f } 		$a_01_1 = {4b 41 52 54 49 43 20 3d 20 22 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } 		$a_01_2 = {54 49 54 41 54 20 3d 20 54 41 65 63 20 2b 20 54 59 69 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}