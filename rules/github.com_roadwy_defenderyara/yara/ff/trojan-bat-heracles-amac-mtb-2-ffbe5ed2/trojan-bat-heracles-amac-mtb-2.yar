rule Trojan_BAT_Heracles_AMAC_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 09 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 04 11 04 06 6f ?? 00 00 0a 00 11 04 05 6f ?? 00 00 0a 00 11 04 0e 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 03 16 03 8e b7 6f ?? 00 00 0a 0b 11 04 6f ?? 00 00 0a 00 07 0c 2b 00 08 2a } 		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}