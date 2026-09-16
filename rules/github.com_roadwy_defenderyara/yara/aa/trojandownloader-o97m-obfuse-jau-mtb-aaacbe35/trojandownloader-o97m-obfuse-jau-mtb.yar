rule TrojanDownloader_O97M_Obfuse_JAU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 01 00 00 65 01 00 00 72 01 00 00 6e 01 00 00 53 01 00 00 68 01 00 00 6c 01 00 00 45 01 00 00 78 01 00 00 63 01 00 00 75 01 00 00 74 01 00 00 41 } 		$a_01_1 = {68 74 74 70 73 3a 2f 2f 6e 6f 6d 7a 6f 6f 2e 6d 6c 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}