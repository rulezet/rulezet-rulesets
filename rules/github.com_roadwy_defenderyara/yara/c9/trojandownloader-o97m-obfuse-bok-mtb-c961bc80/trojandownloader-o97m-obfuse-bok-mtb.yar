rule TrojanDownloader_O97M_Obfuse_BOK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 69 30 30 6a 69 6e 56 22 } 		$a_01_1 = {3d 20 67 4e 53 41 5f 33 62 76 30 5f 76 42 67 2e 45 4f 66 54 62 5f 77 76 4a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}