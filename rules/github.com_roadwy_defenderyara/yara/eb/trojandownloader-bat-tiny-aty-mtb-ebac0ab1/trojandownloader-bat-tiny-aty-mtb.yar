rule TrojanDownloader_BAT_Tiny_ATY_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 22 00 06 6f 17 00 00 0a 07 9a 6f 18 00 00 0a 14 14 6f 19 00 00 0a 2c 02 de 0e de 03 26 de 00 07 17 58 0b 07 1f 0a 32 d9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}