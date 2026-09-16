rule Trojan_BAT_Heracles_AH_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 18 5b 08 06 18 6f 15 00 00 0a 1f 10 28 16 00 00 0a 9c 06 18 58 0a 06 09 32 e3 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}