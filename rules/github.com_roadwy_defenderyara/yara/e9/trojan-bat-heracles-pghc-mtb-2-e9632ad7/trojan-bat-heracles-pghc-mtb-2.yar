rule Trojan_BAT_Heracles_PGHC_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.PGHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 1b 00 07 09 8f ?? 00 00 01 25 71 ?? 00 00 01 08 61 d2 81 ?? 00 00 01 00 09 17 58 0d 09 07 8e 69 fe 04 13 05 11 05 2d d9 } 		$a_03_1 = {03 8e 69 20 ?? ?? 00 00 1f 40 28 ?? 00 00 06 0b 07 7e ?? 00 00 0a 28 ?? 00 00 0a 16 fe 01 13 05 11 05 2d 0d 00 06 28 ?? 00 00 06 26 16 13 04 2b 6d 06 07 03 03 8e 69 12 02 28 ?? 00 00 06 13 05 11 05 2d 0d 00 06 28 ?? 00 00 06 26 16 13 04 2b 4d } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}