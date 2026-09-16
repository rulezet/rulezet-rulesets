rule Trojan_BAT_SpyNoon_SPPO_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 07 11 06 17 6a 58 07 8e 69 6a 5d d4 91 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}