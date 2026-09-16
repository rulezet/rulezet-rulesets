rule TrojanDownloader_BAT_Scarsi_RS_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Scarsi.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 a6 00 00 0a 72 15 0b 00 70 6f a7 00 00 0a 0d 08 8e 69 17 da 13 06 16 13 07 2b 17 } 		$a_01_1 = {08 11 07 09 11 07 09 8e 69 5d 91 08 11 07 91 61 9c 11 07 17 d6 13 07 11 07 11 06 31 e3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}