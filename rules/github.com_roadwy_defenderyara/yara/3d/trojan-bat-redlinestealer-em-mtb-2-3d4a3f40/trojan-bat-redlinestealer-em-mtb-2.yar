rule Trojan_BAT_RedLineStealer_EM_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 fc a1 01 70 72 00 a2 01 70 6f 3e 01 00 0a 72 04 a2 01 70 72 08 a2 01 70 6f 3e 01 00 0a 0b 73 3f 01 00 0a 0c 07 6f 40 01 00 0a 18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f 41 01 00 0a 1f 10 28 42 01 00 0a b4 6f 43 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}