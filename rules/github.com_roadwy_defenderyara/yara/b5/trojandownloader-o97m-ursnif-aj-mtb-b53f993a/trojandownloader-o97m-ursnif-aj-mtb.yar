rule TrojanDownloader_O97M_Ursnif_AJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-10] 20 26 20 [0-30] 2e 78 73 6c 22 2c 20 31 29 } 		$a_03_1 = {26 20 43 68 72 28 [0-08] 28 [0-08] 28 [0-08] 29 2c } 		$a_01_2 = {56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c } 		$a_01_3 = {3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } 		$a_01_4 = {2e 76 61 6c 75 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}