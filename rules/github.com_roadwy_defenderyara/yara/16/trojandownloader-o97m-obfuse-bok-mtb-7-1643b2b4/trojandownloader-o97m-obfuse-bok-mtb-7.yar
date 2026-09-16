rule TrojanDownloader_O97M_Obfuse_BOK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 4b 4c 41 69 52 7a 54 45 68 79 6d 59 4e 34 62 76 6b 22 2c } 		$a_01_1 = {3d 20 70 47 66 44 6c 5f 73 63 44 64 5f 75 33 32 53 2e 48 4e 4a 69 5f 6b 68 69 65 5f 56 6a 4f 44 5f 43 6f 46 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}