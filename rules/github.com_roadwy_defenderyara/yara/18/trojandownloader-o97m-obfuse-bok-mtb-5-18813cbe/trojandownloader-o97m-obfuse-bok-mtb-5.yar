rule TrojanDownloader_O97M_Obfuse_BOK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 66 71 41 67 4e 5f 48 41 45 79 5f 4c 69 59 4f 5f 5a 31 6b } 		$a_01_1 = {3d 20 48 61 45 41 57 5f 6f 5a 75 2e 49 5a 43 48 73 49 72 74 48 78 49 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}