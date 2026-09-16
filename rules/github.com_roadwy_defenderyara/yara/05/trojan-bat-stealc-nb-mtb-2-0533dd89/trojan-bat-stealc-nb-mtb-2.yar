rule Trojan_BAT_StealC_NB_MTB_2{
	meta:
		description = "Trojan:BAT/StealC.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 0e 00 00 04 16 fe 06 ?? 00 00 06 9b 16 2d e5 7e ?? 00 00 04 17 fe 06 ?? 00 00 06 9b 16 2d e0 } 		$a_03_1 = {8d 37 00 00 01 80 ?? 00 00 04 7e ?? 00 00 04 16 fe 06 ?? 00 00 06 9b 7e 0b 00 00 04 17 fe 06 ?? 00 00 06 9b 7e ?? 00 00 04 18 fe 06 ?? 00 00 06 9b } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}