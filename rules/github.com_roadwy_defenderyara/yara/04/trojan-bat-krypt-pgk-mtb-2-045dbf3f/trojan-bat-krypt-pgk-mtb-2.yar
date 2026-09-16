rule Trojan_BAT_Krypt_PGK_MTB_2{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 08 07 06 11 08 58 93 11 06 11 08 08 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 11 08 11 04 fe 04 2d db } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}