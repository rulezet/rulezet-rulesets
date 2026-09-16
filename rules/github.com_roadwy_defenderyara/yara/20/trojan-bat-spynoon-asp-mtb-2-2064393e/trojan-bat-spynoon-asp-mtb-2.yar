rule Trojan_BAT_SpyNoon_ASP_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {15 6a 16 28 ?? ?? ?? 0a 17 8d 3c 00 00 01 0b 07 16 17 9e 07 28 ?? ?? ?? 0a 02 02 7b 12 00 00 04 72 fb 00 00 70 15 16 28 ?? ?? ?? 0a 7d 11 00 00 04 02 6f ?? ?? ?? 06 02 7b 11 00 00 04 17 9a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}