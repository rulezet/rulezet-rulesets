rule Trojan_BAT_Heracles_BAO_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 58 20 00 01 00 00 5d 13 06 11 07 06 11 06 91 58 20 00 01 00 00 5d 13 07 06 11 06 91 13 09 06 11 06 06 11 07 91 9c 06 11 07 11 09 9c 11 05 11 08 02 11 08 91 06 06 11 06 91 06 11 07 91 58 20 00 01 00 00 5d 91 61 d2 9c 11 08 17 58 13 08 11 08 02 8e 69 32 a8 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}