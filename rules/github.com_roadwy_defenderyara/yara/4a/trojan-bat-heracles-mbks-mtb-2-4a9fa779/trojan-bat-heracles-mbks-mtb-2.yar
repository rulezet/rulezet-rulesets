rule Trojan_BAT_Heracles_MBKS_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 09 07 09 8e 69 6a 5d d4 91 61 06 07 17 6a 58 06 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 08 06 07 06 8e 69 6a 5d d4 11 08 20 00 01 00 00 5d d2 9c 07 17 6a 58 0b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}