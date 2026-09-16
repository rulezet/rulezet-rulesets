rule TrojanDownloader_O97M_Donoff_95{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 42 22 0d 0a [0-10] 20 3d 20 22 6f 22 0d 0a [0-10] 20 3d 20 22 27 22 0d 0a [0-10] 20 3d 20 22 54 22 0d 0a [0-10] 20 3d 20 22 20 22 0d 0a [0-10] 20 3d 20 22 20 22 0d 0a [0-10] 20 3d 20 22 5e 22 0d 0a [0-10] 20 3d 20 22 25 22 0d 0a [0-10] 20 3d 20 22 3d 22 0d 0a } 		$a_03_1 = {20 3d 20 53 68 65 6c 6c 28 [0-08] 2c 20 46 61 6c 73 65 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}