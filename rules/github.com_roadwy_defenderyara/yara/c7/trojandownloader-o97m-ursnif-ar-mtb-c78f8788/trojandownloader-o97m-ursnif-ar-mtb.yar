rule TrojanDownloader_O97M_Ursnif_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 } 		$a_01_1 = {62 61 63 2e 39 6b 6f 6e 3d 6c 3f 70 68 70 2e 70 32 33 69 30 6f 69 61 2f 35 38 6f 6c 30 32 65 77 2f 6d 6f 63 2e 38 66 6a 6a 66 62 62 2f 2f 3a 70 74 74 68 22 2c } 		$a_03_2 = {28 22 74 6d 70 22 29 20 26 20 22 5c [0-09] 2e 74 6d 70 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1) >=12
 
}