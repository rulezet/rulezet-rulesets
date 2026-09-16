rule TrojanDownloader_O97M_IcedID_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 5c 6d 31 2e 78 73 6c } 		$a_01_1 = {26 20 22 5c 6d 31 2e 63 6f 6d } 		$a_01_2 = {72 75 6e 20 61 33 38 55 62 35 20 26 20 61 52 6c 4d 79 78 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 6d 45 32 61 6b 20 26 20 61 51 78 6f 33 42 20 26 20 61 6d 45 32 61 6b } 		$a_01_3 = {46 69 6c 65 43 6f 70 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}