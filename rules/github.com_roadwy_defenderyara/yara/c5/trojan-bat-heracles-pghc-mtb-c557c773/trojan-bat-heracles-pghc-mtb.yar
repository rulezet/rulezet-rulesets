rule Trojan_BAT_Heracles_PGHC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PGHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 23 28 ?? 00 00 0a 11 20 28 ?? 00 00 0a 13 24 11 24 8e 69 8d ?? 00 00 01 13 25 16 13 3b 2b 1c 11 25 11 3b 11 24 11 3b 91 11 22 11 3b 11 22 8e 69 5d 91 61 d2 9c 11 3b 17 58 13 3b 11 3b 11 24 8e 69 32 dc } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}