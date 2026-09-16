rule Trojan_BAT_SapphireStealer_ASH_MTB{
	meta:
		description = "Trojan:BAT/SapphireStealer.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2d 01 2a 72 ?? 01 00 70 73 ?? 00 00 0a 25 72 ?? 01 00 70 06 72 ?? 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 25 16 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}