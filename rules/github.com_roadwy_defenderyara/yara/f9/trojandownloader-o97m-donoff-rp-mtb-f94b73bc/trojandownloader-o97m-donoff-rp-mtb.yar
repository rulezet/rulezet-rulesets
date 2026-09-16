rule TrojanDownloader_O97M_Donoff_RP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 3a 61 76 61 72 2e 6f 70 65 6e 22 67 65 74 22 2c 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f 72 6d 78 38 31 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}