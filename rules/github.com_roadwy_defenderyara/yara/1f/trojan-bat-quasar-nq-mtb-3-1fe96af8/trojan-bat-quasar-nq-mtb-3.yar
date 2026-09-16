rule Trojan_BAT_Quasar_NQ_MTB_3{
	meta:
		description = "Trojan:BAT/Quasar.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {1a 8d 39 00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 16 08 6f ?? 00 00 0a 26 } 		$a_01_1 = {53 45 45 44 43 52 41 43 4b 45 52 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {5a 69 75 78 76 77 6c 64 6e 6e 67 69 67 67 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}