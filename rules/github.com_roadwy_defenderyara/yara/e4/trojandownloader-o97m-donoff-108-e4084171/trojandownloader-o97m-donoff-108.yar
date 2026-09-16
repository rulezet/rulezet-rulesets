rule TrojanDownloader_O97M_Donoff_108{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {26 20 66 76 52 41 46 4c 7a 64 20 26 20 64 30 35 32 75 34 20 26 20 47 68 56 6b 64 20 26 20 4e 65 53 6b 54 41 46 62 6a 20 26 20 4a 46 68 50 77 41 71 43 56 20 26 20 43 71 6d 6f 59 20 26 20 57 76 45 34 52 72 20 26 20 4f 58 65 50 30 4c 70 45 0d 0a 65 43 31 67 79 6c 6e 4c 75 20 3d 20 22 41 74 61 4d 5a 22 0d 0a 49 66 20 4d 69 64 28 65 43 31 67 79 6c 6e 4c 75 2c 20 35 29 20 3d 20 22 73 30 78 6e 32 33 22 20 54 68 65 6e } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}