rule Trojan_BAT_Zusy_BAD_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 73 28 00 00 0a 0c 08 07 16 73 29 00 00 0a 0d 73 1e 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 de 34 11 04 2c 07 11 04 6f ?? 00 00 0a dc 09 2c 06 09 6f ?? 00 00 0a dc 08 2c 06 08 6f ?? 00 00 0a dc } 		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } 	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}