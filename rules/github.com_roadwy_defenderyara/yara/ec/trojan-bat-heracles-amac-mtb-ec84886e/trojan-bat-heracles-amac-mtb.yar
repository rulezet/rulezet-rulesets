rule Trojan_BAT_Heracles_AMAC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? 00 00 06 6e 02 07 17 58 02 8e 69 5d 91 28 ?? 00 00 06 6a 59 20 00 01 00 00 6a 58 20 00 01 00 00 6a 5d d2 9c } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}