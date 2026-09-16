rule Trojan_BAT_SpyNoon_ASP_MTB_3{
	meta:
		description = "Trojan:BAT/SpyNoon.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 14 fe 01 13 05 11 05 2c 11 72 c3 00 00 70 06 28 ?? ?? ?? 0a 73 2c 00 00 0a 7a 09 07 6f ?? ?? ?? 0a 13 04 11 04 14 fe 01 13 06 11 06 2c 11 72 e9 00 00 70 07 28 ?? ?? ?? 0a 73 2e 00 00 0a 7a 11 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}