rule TrojanDownloader_BAT_Tiny_ATY_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 3b 00 08 13 04 16 13 05 11 04 12 05 28 ?? ?? ?? 0a 00 08 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 de 0d 11 05 2c 08 11 04 28 ?? ?? ?? 0a 00 dc 00 09 18 58 0d 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d b6 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}