rule TrojanDownloader_O97M_Ursnif_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 31 35 20 2b 20 30 29 20 2b 20 22 48 45 4c 4c 2e 22 } 		$a_03_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 [0-55] 29 2e 54 65 78 74 } 		$a_03_2 = {4f 70 65 6e 20 54 72 69 6d 28 [0-55] 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } 		$a_03_3 = {50 72 69 6e 74 20 23 ?? 2c 20 54 72 69 6d 28 } 		$a_01_4 = {2e 56 61 6c 75 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}