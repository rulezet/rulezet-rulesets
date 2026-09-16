rule TrojanDownloader_O97M_Donoff_SM_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 20 3d 20 22 68 74 74 70 3a 2f 2f 73 71 6c 73 72 76 30 34 2f 52 65 70 6f 72 74 53 65 72 76 65 72 3f 2f 4c 4e 25 32 30 52 65 70 6f 72 74 73 2f 45 78 70 6f 72 74 25 32 30 4d 41 52 2f 41 6e 6f 64 65 6e 70 6c 61 6e 75 6e 67 26 72 73 3a 46 6f 72 6d 61 74 3d 45 58 43 45 4c 4f 50 45 4e 58 4d 4c 22 } 		$a_01_1 = {73 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 4d 65 2e 50 61 74 68 20 26 20 22 5c 41 6e 6f 64 65 6e 70 6c 61 6e 75 6e 67 2e 78 6c 73 78 22 2c 20 32 } 		$a_01_2 = {4b 69 6c 6c 20 4d 65 2e 50 61 74 68 20 26 20 22 5c 41 6e 6f 64 65 6e 70 6c 61 6e 75 6e 67 2e 78 6c 73 78 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}