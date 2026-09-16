rule Trojan_BAT_SpyNoon_AMBG_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 18 5d 3a ?? 00 00 00 72 ?? 00 00 70 28 ?? 00 00 0a 38 ?? 00 00 00 72 ?? 00 00 70 28 ?? 00 00 0a 06 28 ?? 00 00 0a 38 } 		$a_03_1 = {0a 0b 02 28 ?? 00 00 0a 0c 08 17 3b } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}