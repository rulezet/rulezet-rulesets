rule Trojan_BAT_RedLineStealer_EM_MTB_3{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 72 55 84 01 70 72 f9 11 00 70 6f 25 01 00 0a 72 59 84 01 70 72 5d 84 01 70 6f 25 01 00 0a 0b 73 26 01 00 0a 0c 07 6f 04 01 00 0a 18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f 27 01 00 0a 1f 10 28 28 01 00 0a b4 6f 29 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}