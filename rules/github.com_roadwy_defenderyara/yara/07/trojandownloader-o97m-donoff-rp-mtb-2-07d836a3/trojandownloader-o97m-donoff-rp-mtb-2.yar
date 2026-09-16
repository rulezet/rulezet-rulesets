rule TrojanDownloader_O97M_Donoff_RP_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 3a 2f 2f 33 2e 31 31 32 2e 32 34 33 2e 32 38 2f 74 75 6e 2f 37 37 30 35 32 32 31 32 30 35 2e 62 61 74 22 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}