rule TrojanDownloader_O97M_Obfuse_PA{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 72 72 61 79 28 [0-10] 2c 20 [0-10] 2c 20 [0-10] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 [0-10] 28 [0-10] 2e 54 65 78 74 42 6f 78 31 29 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}