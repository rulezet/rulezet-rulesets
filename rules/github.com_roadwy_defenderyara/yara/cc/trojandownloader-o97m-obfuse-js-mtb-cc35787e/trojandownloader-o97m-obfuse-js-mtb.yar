rule TrojanDownloader_O97M_Obfuse_JS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 64 61 78 61 73 64 61 73 78 61 73 64 61 73 64 73 64 64 6f 64 6b 61 73 6f 64 6b 61 6f 73 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}