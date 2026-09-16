rule TrojanDownloader_BAT_Banload_AM{
	meta:
		description = "TrojanDownloader:BAT/Banload.AM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 69 00 6c 00 6c 00 69 00 6f 00 6e 00 63 00 61 00 72 00 72 00 6f 00 73 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 63 00 61 00 72 00 73 00 68 00 64 00 62 00 66 00 76 00 2e 00 7a 00 69 00 70 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}