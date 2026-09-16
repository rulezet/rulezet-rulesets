rule Trojan_BAT_Rozena_NRO_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 72 86 12 00 70 28 ?? 00 00 06 0d 73 ?? 00 00 0a 13 04 06 28 ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 08 09 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 06 11 06 73 ?? 00 00 0a 13 07 11 07 } 		$a_01_1 = {43 61 6c 69 73 74 69 72 6d 61 46 6f 6e 6b 73 69 79 6f 6e 75 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}