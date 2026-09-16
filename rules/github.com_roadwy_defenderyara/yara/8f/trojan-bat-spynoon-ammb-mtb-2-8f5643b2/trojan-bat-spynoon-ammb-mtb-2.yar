rule Trojan_BAT_SpyNoon_AMMB_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 6a 07 11 ?? 17 6a 58 07 8e 69 6a 5d d4 91 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}