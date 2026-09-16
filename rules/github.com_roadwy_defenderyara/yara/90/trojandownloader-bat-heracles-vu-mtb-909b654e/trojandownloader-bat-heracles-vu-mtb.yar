rule TrojanDownloader_BAT_Heracles_VU_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 06 9e 06 17 58 0a 06 20 ff 00 00 00 fe 03 16 fe 01 13 0d 11 0d 2d e7 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}