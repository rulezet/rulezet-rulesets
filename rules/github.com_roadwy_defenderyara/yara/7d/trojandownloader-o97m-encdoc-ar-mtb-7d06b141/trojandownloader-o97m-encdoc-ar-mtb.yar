rule TrojanDownloader_O97M_EncDoc_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 48 41 36 4c 79 38 78 4f 54 49 75 4d 6a 4d 32 4c 6a 45 33 4f 43 34 34 4d 43 38 33 65 69 38 77 4e 6a 45 33 4e 7a 63 7a 4c 6d 70 77 } 		$a_00_1 = {63 31 78 51 64 57 4a 73 61 57 4e 63 64 32 68 77 5a 6e 64 72 63 6e 56 73 4c 6d 56 34 5a 53 4a 39 49 67 3d 3d } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}