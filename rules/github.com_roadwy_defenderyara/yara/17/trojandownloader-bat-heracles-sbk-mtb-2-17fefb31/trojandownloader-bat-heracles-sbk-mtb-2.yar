rule TrojanDownloader_BAT_Heracles_SBK_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 09 00 00 06 25 11 00 28 01 00 00 0a 7d 02 00 00 04 6f 07 00 00 06 38 00 00 00 00 2a 7e 06 00 00 04 28 0f 00 00 06 28 0c 00 00 06 13 00 38 cd ff ff ff } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}