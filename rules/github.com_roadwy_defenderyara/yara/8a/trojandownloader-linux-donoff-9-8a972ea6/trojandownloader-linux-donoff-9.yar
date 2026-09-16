rule TrojanDownloader_Linux_Donoff_9{
	meta:
		description = "TrojanDownloader:Linux/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 43 44 46 20 3d 20 50 55 76 64 20 2b 20 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28 [0-10] 29 20 2b 20 45 45 57 45 46 20 2b 20 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28 } 		$a_01_1 = {43 61 6c 6c 20 50 50 75 69 79 66 68 46 73 64 66 2e 4f 70 65 6e 28 75 42 49 6e 7a 7a 4f 53 56 4e 6d 42 75 65 4c 4f 6a 4c 50 65 28 22 5d 5c 60 61 22 29 2c 20 43 43 44 46 2c 20 46 61 6c 73 65 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}