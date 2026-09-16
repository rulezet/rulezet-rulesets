rule Trojan_BAT_Heracles_AH_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {18 5b 0b 16 0d 2b 27 72 01 00 00 70 02 09 18 5a 18 6f 09 00 00 0a 28 0a 00 00 0a 1f 10 28 0b 00 00 0a 13 04 06 09 11 04 d2 9c 09 17 58 0d 09 07 32 d5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}