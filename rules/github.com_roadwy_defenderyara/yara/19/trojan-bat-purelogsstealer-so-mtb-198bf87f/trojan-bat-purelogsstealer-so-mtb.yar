rule Trojan_BAT_PureLogsStealer_SO_MTB{
	meta:
		description = "Trojan:BAT/PureLogsStealer.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 05 1f 25 61 13 05 11 05 1f 29 59 45 04 00 00 00 0b 00 00 00 17 00 00 00 32 00 00 00 39 00 00 00 1f 26 28 17 02 00 06 13 05 2b d4 00 1f 27 28 17 02 00 06 13 05 2b c8 07 06 08 18 6f 12 00 00 0a 1f 10 28 13 00 00 0a 6f 14 00 00 0a 1f 0e 13 05 2b ad 00 1f 0c 13 05 2b a6 } 		$a_81_1 = {24 64 37 36 33 66 30 34 66 2d 66 37 30 65 2d 34 34 31 64 2d 62 32 62 62 2d 34 62 35 64 34 66 64 36 36 64 64 39 } 		$a_81_2 = {44 65 63 72 79 70 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}