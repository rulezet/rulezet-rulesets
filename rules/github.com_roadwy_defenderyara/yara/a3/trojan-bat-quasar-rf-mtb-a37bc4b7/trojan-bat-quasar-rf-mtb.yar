rule Trojan_BAT_Quasar_RF_MTB{
	meta:
		description = "Trojan:BAT/Quasar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 11 08 58 20 ee 6b b4 e8 11 00 61 11 01 61 61 11 0b 11 00 20 9b e6 45 58 58 11 01 59 5f 61 13 41 } 		$a_01_1 = {11 08 58 20 ee 6b b4 e8 11 00 61 11 01 61 61 11 0b 11 00 20 9b e6 45 58 58 11 01 59 5f 61 13 41 } 		$a_01_2 = {11 02 11 01 1a 62 11 01 1b 63 61 11 01 58 11 03 11 00 11 03 1f 0b 63 19 5f 94 58 61 59 13 02 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}