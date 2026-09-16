rule TrojanDownloader_O97M_Donoff_48{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 70 6f 77 65 72 22 20 26 20 22 73 68 22 20 26 20 22 65 6c 6c 22 20 26 20 22 2e 65 22 20 26 20 22 78 65 20 2d 65 22 20 26 20 22 78 65 63 20 62 22 20 26 20 22 79 70 61 73 22 20 26 20 22 73 20 2d 45 22 20 26 20 22 6e 63 20 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}