rule TrojanDownloader_O97M_Obfuse_BOK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 3a 2f 2f 31 39 34 2e 31 39 35 2e 32 30 39 2e 38 38 2f 61 70 70 6c 61 75 63 68 68 2e 65 78 65 } 		$a_01_1 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 73 3a 2f 2f 61 72 74 75 72 6b 61 72 6f 6c 63 7a 61 6b 73 68 69 6f 6c 61 2e 63 6f 6d 2f 6a 61 7a 7a 2f 74 67 36 4e 72 6d 71 39 74 44 4f 37 62 54 49 2e 65 78 65 } 		$a_01_2 = {6f 75 74 46 49 6c 45 20 6f 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}