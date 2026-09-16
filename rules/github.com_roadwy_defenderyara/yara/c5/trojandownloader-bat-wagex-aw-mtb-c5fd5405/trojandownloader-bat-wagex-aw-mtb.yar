rule TrojanDownloader_BAT_Wagex_AW_MTB{
	meta:
		description = "TrojanDownloader:BAT/Wagex.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 18 2d 03 26 2b 1b 0a 2b fb 00 02 72 01 00 00 70 28 ?? ?? ?? 06 1a 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c e5 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}