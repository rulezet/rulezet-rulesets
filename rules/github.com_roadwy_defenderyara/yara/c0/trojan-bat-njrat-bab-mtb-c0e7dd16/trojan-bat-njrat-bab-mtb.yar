rule Trojan_BAT_NjRat_BAB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 08 07 1a 07 8e b7 1a da ?? ?? ?? ?? ?? 00 09 17 da 17 d6 8d 3c 00 00 01 13 04 08 16 6a ?? ?? ?? ?? ?? 00 00 08 16 73 74 00 00 0a 13 05 00 11 05 11 04 16 11 04 8e b7 ?? ?? ?? ?? ?? 26 00 de 18 11 05 14 fe 01 16 fe 01 13 06 11 06 2c 08 11 05 ?? ?? ?? ?? ?? 00 00 dc 28 76 00 00 0a 11 04 16 11 04 8e b7 ?? ?? ?? ?? ?? 0a de 19 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}