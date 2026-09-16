rule Trojan_BAT_Heracles_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 0b 91 1f 18 62 11 04 11 0b 17 58 91 1f 10 62 60 11 04 11 0b 18 58 91 1e 62 60 11 04 11 0b 19 58 91 60 } 		$a_01_1 = {11 08 2c 06 11 07 13 06 2b 13 11 07 17 58 13 07 11 07 11 04 8e 69 11 05 8e 69 59 31 b9 } 	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}