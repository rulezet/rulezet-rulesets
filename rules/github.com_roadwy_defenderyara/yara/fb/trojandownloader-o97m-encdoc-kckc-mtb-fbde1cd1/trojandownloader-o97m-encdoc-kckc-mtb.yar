rule TrojanDownloader_O97M_EncDoc_KCKC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KCKC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 63 6b 69 6e 6e 65 79 74 69 67 68 65 2e 63 6f 6d 2f 6e 65 77 6d 6f 6e 2f 63 61 6c 63 2f 41 74 74 61 63 6b 2e 6a 70 67 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}