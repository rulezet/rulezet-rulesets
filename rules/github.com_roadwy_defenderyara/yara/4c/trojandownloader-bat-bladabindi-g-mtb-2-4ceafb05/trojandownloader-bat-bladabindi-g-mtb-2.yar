rule TrojanDownloader_BAT_Bladabindi_G_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 60 00 00 0a 0a 06 [0-30] 6f 61 00 00 0a 0b 07 [0-30] 28 0c 00 00 06 28 62 00 00 0a 0c 28 63 00 00 0a [0-40] 28 0c 00 00 06 17 17 8d 02 00 00 01 13 06 11 06 16 08 a2 11 06 28 64 00 00 0a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}