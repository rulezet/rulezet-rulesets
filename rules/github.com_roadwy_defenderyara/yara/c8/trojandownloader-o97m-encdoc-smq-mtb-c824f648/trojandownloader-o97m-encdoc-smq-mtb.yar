rule TrojanDownloader_O97M_EncDoc_SMQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 30 32 34 39 35 30 30 32 25 4f 50 2f 6b 72 61 6c 43 30 32 25 6c 75 61 50 2f 6d 6f 63 2e 6d 61 6b 63 69 6c 63 74 73 75 6a 2f 2f 3a 73 70 74 74 68 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}