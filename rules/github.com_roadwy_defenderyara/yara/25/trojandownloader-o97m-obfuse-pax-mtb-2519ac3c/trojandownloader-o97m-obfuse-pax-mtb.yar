rule TrojanDownloader_O97M_Obfuse_PAX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 61 28 [0-06] 29 20 41 73 20 56 61 72 69 61 6e 74 } 		$a_01_1 = {3d 20 46 72 65 65 46 69 6c 65 } 		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 74 65 73 74 5f 6d 61 6b 65 5f 64 6f 63 2e 65 78 65 } 		$a_03_3 = {3d 20 53 68 65 6c 6c 28 [0-15] 2c 20 31 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}