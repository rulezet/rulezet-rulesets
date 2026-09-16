rule TrojanDownloader_O97M_Adnel_6{
	meta:
		description = "TrojanDownloader:O97M/Adnel,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 52 54 59 67 75 68 69 68 64 66 66 59 54 55 64 73 66 28 29 ?? ?? 52 44 46 43 47 56 48 6a 64 61 64 20 3d 20 57 45 44 52 54 59 67 75 66 2e 67 66 64 63 77 65 66 77 65 72 66 66 66 ?? ?? 53 68 65 6c 6c 20 52 44 46 43 47 56 48 6a 64 61 64 2c 20 76 62 48 69 64 65 ?? ?? 45 6e 64 20 53 75 62 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}