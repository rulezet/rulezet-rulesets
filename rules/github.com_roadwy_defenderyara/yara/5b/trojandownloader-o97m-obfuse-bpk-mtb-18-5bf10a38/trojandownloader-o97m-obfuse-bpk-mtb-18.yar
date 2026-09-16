rule TrojanDownloader_O97M_Obfuse_BPK_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 } 		$a_01_1 = {68 22 20 2b 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 5c 5c 22 20 2b 20 22 6a 2e 22 20 2b 20 22 6d 70 5c 22 20 2b 20 22 71 61 73 61 78 61 68 6e 6e 38 33 6a 73 38 78 61 73 78 6a 78 39 61 73 78 6a } 		$a_01_2 = {53 68 65 6c 6c 20 22 50 69 6e 67 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}