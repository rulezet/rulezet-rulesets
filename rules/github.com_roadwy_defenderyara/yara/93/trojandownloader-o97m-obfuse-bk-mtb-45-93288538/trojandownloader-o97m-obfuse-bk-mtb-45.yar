rule TrojanDownloader_O97M_Obfuse_BK_MTB_45{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 50 49 4e 43 48 50 45 4e 4e 59 5f 45 4e 4c 41 52 44 49 4e 47 5f 54 45 4c 45 53 45 53 5f 54 2e 46 4c 49 4e 44 45 52 41 55 52 4f 52 41 4c 50 59 52 4f 53 54 41 54 53 } 		$a_01_1 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 73 77 61 69 6e 69 73 68 6e 65 73 73 65 73 5f 6d 61 75 73 6f 6c 65 61 2e 66 69 6e 6f 63 63 68 69 6f 64 75 63 6b 69 65 73 74 61 6e 61 67 72 61 6d 6d 61 74 69 73 65 28 29 } 		$a_01_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4c 65 6e 28 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}