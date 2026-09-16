rule TrojanDownloader_O97M_Obfuse_DO{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DO,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 7a 28 29 } 		$a_03_1 = {3d 20 53 68 65 6c 6c 28 [0-10] 2c 20 30 29 } 		$a_03_2 = {3d 20 52 6f 75 6e 64 28 [0-08] 2e [0-10] 29 } 		$a_03_3 = {3d 20 53 67 6e 28 [0-04] 29 } 		$a_01_4 = {43 61 6c 6c 20 7a } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}