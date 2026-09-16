rule TrojanDownloader_O97M_Obfuse_BOK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 68 50 41 66 68 70 55 6a 22 2c } 		$a_01_1 = {3d 20 7a 5a 48 36 49 49 67 6b 51 66 77 2e 77 65 34 6b 59 4e 69 78 68 6b 7a 47 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}