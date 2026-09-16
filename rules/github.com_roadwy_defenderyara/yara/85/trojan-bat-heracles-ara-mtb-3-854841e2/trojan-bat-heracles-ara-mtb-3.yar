rule Trojan_BAT_Heracles_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 07 91 7e ?? ?? ?? ?? 07 1e 5d 1f 1f 5f 63 d2 61 d2 0c 08 19 63 08 1b 62 60 d2 0c 08 7e ?? ?? ?? ?? 20 00 01 00 00 28 ?? ?? ?? 06 5a 20 00 01 00 00 5d d2 0c 06 07 08 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d b7 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}