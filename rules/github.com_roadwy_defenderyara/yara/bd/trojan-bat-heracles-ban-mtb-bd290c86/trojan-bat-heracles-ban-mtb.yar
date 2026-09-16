rule Trojan_BAT_Heracles_BAN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 17 58 20 00 01 00 00 5d 13 07 11 08 07 11 07 91 58 20 00 01 00 00 5d 13 08 07 11 07 91 13 09 07 11 07 07 11 08 91 9c 07 11 08 11 09 9c 08 11 06 02 11 06 91 07 07 11 07 91 07 11 08 91 58 20 00 01 00 00 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 02 8e 69 32 a9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}