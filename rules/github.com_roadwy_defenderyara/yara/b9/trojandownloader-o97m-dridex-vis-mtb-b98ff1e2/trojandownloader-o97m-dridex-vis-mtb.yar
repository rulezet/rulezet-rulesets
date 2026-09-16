rule TrojanDownloader_O97M_Dridex_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 61 70 70 36 2e 73 61 6c 65 73 64 61 74 61 67 65 6e 65 72 61 74 6f 72 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 77 70 2d 61 6c 6c 2d 69 6d 70 6f 72 74 2d 70 72 6f 2f 63 6c 61 73 73 65 73 2f 50 48 50 45 78 63 65 6c 2f 44 30 39 50 6f 31 52 67 2e 70 68 70 } 		$a_01_1 = {2f 2f 77 6f 6c 66 69 78 2e 67 61 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 73 6f 64 69 75 6d 5f 63 6f 6d 70 61 74 2f 73 72 63 2f 43 6f 72 65 2f 42 61 73 65 36 34 2f 34 39 57 57 35 72 50 79 44 2e 70 68 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}