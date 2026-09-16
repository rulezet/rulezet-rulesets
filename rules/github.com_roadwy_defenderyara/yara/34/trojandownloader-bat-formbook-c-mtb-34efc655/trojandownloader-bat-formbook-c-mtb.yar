rule TrojanDownloader_BAT_FormBook_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 72 01 00 00 70 73 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 03 20 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}