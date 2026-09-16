rule Trojan_BAT_Krypt_PGK_MTB{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 4a 09 61 54 09 17 62 09 1d 63 60 0d 00 11 09 17 58 13 09 11 09 06 8e 69 fe 04 13 0a 11 0a 2d d6 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}