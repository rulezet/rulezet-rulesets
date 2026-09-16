rule TrojanDownloader_O97M_Emotet_AMDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 5e 68 5e 74 5e 61 20 68 5e 74 5e 74 70 3a 2f 5e 2f 30 5e 78 35 5e 62 66 5e 30 37 5e 36 61 5e 38 2f 73 65 2f 73 2e 68 74 6d 6c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}