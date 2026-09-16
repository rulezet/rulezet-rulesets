rule Trojan_BAT_Marsilia_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 0b 03 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 0c 06 02 07 6f ?? 00 00 0a 0d 09 08 16 08 8e 69 6f ?? 00 00 0a 13 04 11 04 13 05 dd } 		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}