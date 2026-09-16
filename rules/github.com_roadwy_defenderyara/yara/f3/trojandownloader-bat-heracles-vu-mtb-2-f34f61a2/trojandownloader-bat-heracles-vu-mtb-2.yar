rule TrojanDownloader_BAT_Heracles_VU_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 2b 3a 08 07 6f 19 00 00 0a 5d 6f 1a 00 00 0a 61 d2 9c 16 2d df 1a 2c dc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}