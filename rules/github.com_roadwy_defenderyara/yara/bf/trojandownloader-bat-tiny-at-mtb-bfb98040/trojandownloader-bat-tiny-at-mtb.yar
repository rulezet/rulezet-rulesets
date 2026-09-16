rule TrojanDownloader_BAT_Tiny_AT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 03 00 00 0a 0a 06 6f 04 00 00 0a 72 01 00 00 70 6f 05 00 00 0a 06 6f 04 00 00 0a 72 11 00 00 70 6f 06 00 00 0a 06 6f 04 00 00 0a 17 6f 07 00 00 0a 06 6f 04 00 00 0a 17 6f 08 00 00 0a 06 6f 09 00 00 0a 26 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}