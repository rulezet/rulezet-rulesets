rule TrojanDownloader_BAT_Ader_ARA_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/Ader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 15 00 06 08 07 09 91 06 08 91 61 28 ?? ?? ?? 0a 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 05 11 05 2d df 00 08 17 58 0c 08 06 8e 69 fe 04 13 05 11 05 2d c9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}