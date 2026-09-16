rule Trojan_BAT_Razy_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 05 2b 3c 12 05 28 70 00 00 0a 0b 00 07 28 2a 00 00 06 16 fe 01 13 04 11 04 2d 04 07 0d de 47 07 28 2b 00 00 06 0c 08 7e 5a 00 00 0a 28 71 00 00 0a 16 fe 01 13 04 11 04 2d 04 } 		$a_01_1 = {13 04 2b 2b 12 04 28 70 00 00 0a 0b 00 07 28 29 00 00 06 0c 08 28 73 00 00 0a 0d 09 2d 08 03 08 6f 74 00 00 0a 00 07 03 28 2c 00 00 06 00 00 12 04 28 72 00 00 0a 0d 09 2d ca } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}