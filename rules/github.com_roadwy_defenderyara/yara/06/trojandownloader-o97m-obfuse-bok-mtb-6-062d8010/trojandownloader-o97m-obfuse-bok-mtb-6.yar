rule TrojanDownloader_O97M_Obfuse_BOK_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 59 71 44 53 57 30 55 58 79 71 5a 43 48 39 4a } 		$a_01_1 = {3d 20 4e 70 4a 47 58 5f 76 34 47 76 5f 52 6d 4f 5f 31 6d 4d 58 2e 4a 51 62 41 4e 5f 54 6d 6b 4c 5f 68 6d 35 5f 67 69 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}