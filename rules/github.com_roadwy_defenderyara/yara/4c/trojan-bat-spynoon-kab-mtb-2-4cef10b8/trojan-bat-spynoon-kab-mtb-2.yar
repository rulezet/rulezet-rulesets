rule Trojan_BAT_SpyNoon_KAB_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 11 0a 11 06 8e 69 5d 11 06 11 0a 11 06 8e 69 5d 91 11 07 11 0a 1f 16 5d 6f ?? ?? 00 0a 61 28 ?? ?? 00 0a 11 06 11 0a 17 58 11 06 8e 69 5d 91 28 ?? ?? 00 0a 59 20 ?? ?? 00 00 58 20 ?? ?? 00 00 5d 28 ?? ?? 00 0a 9c 00 11 0a 15 58 13 0a 11 0a 16 fe 04 16 fe 01 13 0b 11 0b 2d a1 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}