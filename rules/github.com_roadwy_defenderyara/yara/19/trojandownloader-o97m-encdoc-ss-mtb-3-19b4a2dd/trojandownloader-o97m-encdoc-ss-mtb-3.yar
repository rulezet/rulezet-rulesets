rule TrojanDownloader_O97M_EncDoc_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 73 74 61 67 69 6e 67 2e 67 61 69 61 66 61 63 74 75 72 61 63 69 6f 6e 2e 63 6f 6d 2f 70 72 6f 64 75 63 63 69 6f 6e 2f 76 34 2f 69 6e 63 6c 75 64 65 2f 6c 69 62 2f 70 68 70 71 72 63 6f 64 65 2f 63 61 63 68 65 2f 72 7a 6b 4e 75 71 70 36 6d 31 68 6f 59 2e 70 68 70 } 		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}