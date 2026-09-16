rule TrojanDownloader_O97M_Obfuse_PS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 2d 57 6f 72 6d 2e 4b 61 6d 69 6c 61 } 		$a_00_1 = {4b 69 6c 6c 20 22 43 3a 5c 6b 61 6d 61 2e 64 6c 6c } 		$a_00_2 = {77 73 68 2e 52 75 6e 20 22 43 3a 5c 6b 61 6d 5f 64 72 6f 70 2e 76 62 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}