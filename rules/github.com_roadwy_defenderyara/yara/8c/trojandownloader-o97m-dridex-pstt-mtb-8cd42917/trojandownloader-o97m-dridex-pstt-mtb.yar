rule TrojanDownloader_O97M_Dridex_PSTT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 0c 02 00 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4d 61 63 72 6f 31 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 61 6c 6c 75 73 65 72 73 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 43 74 43 53 49 2e 73 63 74 22 90 0c 02 00 45 6e 64 20 53 75 62 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}