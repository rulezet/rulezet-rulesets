rule Trojan_BAT_SpyNoon_AMBG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 11 10 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}