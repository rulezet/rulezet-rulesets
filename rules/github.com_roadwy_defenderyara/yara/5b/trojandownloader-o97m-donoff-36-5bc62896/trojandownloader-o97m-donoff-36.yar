rule TrojanDownloader_O97M_Donoff_36{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3d 20 22 77 53 22 20 26 20 43 68 72 28 39 39 29 20 26 20 22 52 49 22 20 26 20 22 70 54 2e 53 68 45 22 20 26 20 22 4c 4c 22 [0-20] 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}