rule Trojan_BAT_DarkTortilla_PGDA_MTB_2{
	meta:
		description = "Trojan:BAT/DarkTortilla.PGDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 10 11 04 6f ?? 00 00 0a 13 06 38 ?? ?? ff ff 11 07 28 ?? 00 00 06 13 07 38 ?? ?? ff ff 03 72 59 0e 00 70 28 ?? 00 00 0a 3a ?? ?? ff ff 38 ?? ?? ff ff 11 07 1d 62 11 07 17 63 60 d2 13 07 38 ?? ?? ff ff } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}