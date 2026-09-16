rule TrojanDownloader_O97M_Donoff_116{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {69 6e 74 6e 75 6d 20 3d 20 2d 31 20 2a 20 69 6e 74 6e 75 6d 20 2b 20 4c 65 6e 28 43 67 76 64 6e 74 29 0d 0a 76 69 6e 31 20 3d 20 35 20 2b 20 6a 75 73 74 50 72 69 6e 74 32 28 29 0d 0a 49 66 20 31 20 3d 20 76 69 6e 31 20 2b 20 69 6e 74 6e 75 6d 20 54 68 65 6e 20 53 68 65 6c 6c 20 4e 6f 6b 61 74 50 6f 6b 61 2c 20 69 6e 74 6e 75 6d 0d 0a 4e 6f 6b 61 74 50 6f 6b 61 20 3d 20 4e 6f 6b 61 74 50 6f 6b 61 20 2b 20 22 36 46 37 64 45 72 22 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}