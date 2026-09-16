rule Trojan_BAT_QuasarRAT_BAB_MTB_4{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 08 11 0e 11 0f ?? ?? 00 00 0a 13 10 11 0c 11 0d 25 17 58 13 0d 12 10 ?? ?? 00 00 0a 9c 11 0d 11 0b fe 04 16 fe 01 13 1d 11 1d 2d 11 11 0c 11 0d 25 17 58 13 0d 12 10 ?? ?? 00 00 0a 9c 11 0d 11 0b fe 04 16 fe 01 13 1d 11 1d 2d 11 11 0c 11 0d 25 17 58 13 0d 12 10 ?? ?? 00 00 0a 9c 11 0e 17 58 13 0e 11 0e 11 08 ?? ?? 00 00 0a fe 04 13 1d 11 1d 2d 0b 00 16 13 0e 11 0f 17 58 13 0f 00 00 11 0d 11 0b fe 04 13 1d 11 1d 3a 6f ff ff ff } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}