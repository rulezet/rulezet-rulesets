rule TrojanDownloader_BAT_Tiny_ATY_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 11 04 6f ?? ?? ?? 0a 8c 01 00 00 01 28 ?? ?? ?? 0a 13 05 11 05 28 ?? ?? ?? 06 39 03 00 00 00 11 05 2a 11 04 17 58 13 04 11 04 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}