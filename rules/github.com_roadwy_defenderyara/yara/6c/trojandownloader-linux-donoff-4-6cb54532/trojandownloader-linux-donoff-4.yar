rule TrojanDownloader_Linux_Donoff_4{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {62 6f 74 2e 6a 61 72 } 		$a_01_1 = {45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 20 22 5c 22 20 26 } 		$a_01_2 = {43 68 61 6e 67 65 54 65 78 74 20 30 2c 20 22 6f 70 65 6e 22 2c 20 5f } 		$a_00_3 = {22 69 6e 76 6f 69 63 65 2e 6a 61 72 22 } 		$a_01_4 = {3d 20 22 31 39 32 2e 39 39 2e 31 38 31 2e } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}