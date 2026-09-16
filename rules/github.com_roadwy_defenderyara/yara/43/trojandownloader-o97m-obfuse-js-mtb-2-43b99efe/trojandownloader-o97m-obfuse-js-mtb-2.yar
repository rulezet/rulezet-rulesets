rule TrojanDownloader_O97M_Obfuse_JS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 68 0b 00 00 65 6c 6c 45 78 65 63 75 74 65 41 } 		$a_00_1 = {55 52 10 00 00 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_00_2 = {43 3a 5c 55 73 65 72 73 5c 1f 00 00 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 48 65 6c 6c 6f 57 6f 72 6c 64 2e 65 78 65 } 		$a_00_3 = {68 74 74 70 3a 2f 2f 39 33 2e 31 31 35 2e 31 39 2e 32 32 36 2f 65 76 6c 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}