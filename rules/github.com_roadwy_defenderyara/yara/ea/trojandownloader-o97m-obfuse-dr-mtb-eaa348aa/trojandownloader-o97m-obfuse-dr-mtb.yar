rule TrojanDownloader_O97M_obfuse_DR_MTB{
	meta:
		description = "TrojanDownloader:O97M/obfuse.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 } 		$a_00_1 = {53 75 62 20 6d 61 6c 69 63 69 6f 75 73 28 29 } 		$a_03_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 5c 5c 31 37 32 2e 31 36 2e 32 31 35 2e 31 33 31 5c [0-09] 5c 6b 61 70 69 74 61 6e 68 61 63 6b 2e 64 6c 6c } 		$a_00_3 = {52 75 6e 20 43 61 6c 63 75 6c 61 74 6f 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}