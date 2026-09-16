rule TrojanDownloader_O97M_Obfuse_RPI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RPI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 69 31 74 6f 6c 65 6e 78 64 65 63 72 79 70 74 65 64 64 65 63 72 79 70 74 65 64 63 68 72 61 73 63 6d 69 64 78 69 31 78 6f 72 6b 65 79 6e 65 78 74 69 } 		$a_01_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 77 73 63 72 69 70 74 73 68 65 6c 6c 72 75 6e 64 65 63 72 79 70 74 65 64 30 65 6e 64 73 75 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}