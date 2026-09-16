rule TrojanDownloader_O97M_EncDoc_PKJA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKJA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 45 54 55 [0-20] 3a 2f [0-40] 2e [0-05] 2f [0-20] 2f [0-20] 2f 22 2c 22 [0-20] 3a 2f 2f [0-40] 2e [0-05] 2f [0-20] 2f [0-20] 2f 22 2c 22 [0-20] 3a 2f 2f [0-40] 2e [0-03] 2f [0-20] 2f [0-20] 2f 22 2c 22 [0-20] 3a 2f 2f [0-40] 2e [0-03] 2f [0-20] 2f [0-20] 2f 22 2c 22 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}