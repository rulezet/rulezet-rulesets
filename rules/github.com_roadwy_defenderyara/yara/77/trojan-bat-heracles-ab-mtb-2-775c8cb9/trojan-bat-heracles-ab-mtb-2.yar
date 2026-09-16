rule Trojan_BAT_Heracles_AB_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 11 07 16 91 2d 02 2b 1e 11 06 16 9a 28 ?? 00 00 0a d0 ?? 00 00 1b 28 ?? 00 00 0a 28 ?? ?? 00 0a 74 ?? 00 00 1b 0d 11 08 28 ?? ?? 00 0a 13 05 11 05 16 fe 02 13 09 11 09 2c 0d 11 04 09 16 11 05 6f ?? ?? 00 0a 00 00 00 00 11 05 16 fe 02 13 0a 11 0a 3a 6a ff ff ff } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}