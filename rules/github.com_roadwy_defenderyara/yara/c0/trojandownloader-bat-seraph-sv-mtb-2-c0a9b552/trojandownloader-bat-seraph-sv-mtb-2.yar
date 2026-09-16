rule TrojanDownloader_BAT_Seraph_SV_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 6f 03 00 00 0a 13 25 11 0c 11 25 11 15 59 61 13 0c 11 15 19 11 0c 58 1e 63 59 13 15 11 0d 6f 37 00 00 06 2d d9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}