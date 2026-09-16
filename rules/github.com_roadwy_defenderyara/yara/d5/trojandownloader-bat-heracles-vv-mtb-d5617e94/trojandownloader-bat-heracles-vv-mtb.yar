rule TrojanDownloader_BAT_Heracles_VV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 72 15 00 00 70 6f 18 00 00 0a 0a dd 0d 00 00 00 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}