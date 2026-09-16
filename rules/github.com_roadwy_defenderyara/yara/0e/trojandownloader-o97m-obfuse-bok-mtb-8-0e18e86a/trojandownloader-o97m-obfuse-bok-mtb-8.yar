rule TrojanDownloader_O97M_Obfuse_BOK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 42 47 4e 41 6e 5f 64 37 78 5f 75 4b 55 20 4e 30 56 72 74 5f 50 6e 79 5f 4a 42 5a 63 22 } 		$a_01_1 = {3d 20 66 73 6b 63 39 5f 75 68 6c 35 5f 63 45 7a 34 2e 79 55 4d 4b 52 5f 6d 35 59 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}