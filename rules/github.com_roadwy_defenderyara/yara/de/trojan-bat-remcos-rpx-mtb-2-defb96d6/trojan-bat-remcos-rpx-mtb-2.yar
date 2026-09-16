rule Trojan_BAT_Remcos_RPX_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 17 13 04 16 13 05 2b 23 00 06 09 11 05 58 91 07 11 05 91 fe 01 16 fe 01 13 06 11 06 2c 06 00 16 13 04 2b 14 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 07 11 07 2d d0 } 		$a_01_1 = {40 00 72 00 68 00 4d 00 2a 00 41 00 7a 00 41 00 21 00 37 00 25 00 63 00 40 00 50 00 34 00 6f 00 62 00 7a 00 44 00 38 00 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}