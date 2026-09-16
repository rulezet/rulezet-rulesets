rule TrojanDownloader_O97M_Obfuse_BOK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 54 73 35 62 62 6a 46 39 53 2c } 		$a_01_1 = {3d 20 61 42 64 7a 4d 5f 55 77 55 5f 77 4f 61 2e 52 59 4b 66 32 6d 48 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}