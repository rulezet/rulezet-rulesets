rule TrojanDownloader_O97M_Obfuse_BPK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 56 50 68 70 67 52 51 5a 59 20 2b 20 4f 77 32 49 55 56 45 4f 61 20 2b 20 77 77 68 52 4b 42 39 34 4f 66 6c 42 45 48 56 68 75 20 2b 20 4f 66 6c 42 45 48 56 68 75 29 29 } 		$a_01_1 = {4f 66 6c 42 45 48 56 68 75 20 3d 20 22 63 68 64 6d 62 6a 68 62 67 68 64 65 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}