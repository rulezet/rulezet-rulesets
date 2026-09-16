rule TrojanDownloader_O97M_Obfuse_BOK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 66 72 69 54 6b 77 51 44 53 20 26 } 		$a_01_1 = {3d 20 44 68 5a 7a 46 38 65 74 59 76 31 6e 49 2e 4a 4c 30 6c 6a 51 77 66 75 4b 6f 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}