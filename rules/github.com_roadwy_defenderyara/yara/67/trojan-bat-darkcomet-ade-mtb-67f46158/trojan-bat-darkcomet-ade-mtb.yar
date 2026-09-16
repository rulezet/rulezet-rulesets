rule Trojan_BAT_DarkComet_ADE_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {94 d6 09 11 08 94 d6 20 00 01 00 00 5d 0a 11 07 11 08 94 13 0c 11 07 11 08 11 07 06 94 9e 11 07 06 11 0c 9e 12 08 28 ?? ?? ?? 0a 11 08 17 da 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}