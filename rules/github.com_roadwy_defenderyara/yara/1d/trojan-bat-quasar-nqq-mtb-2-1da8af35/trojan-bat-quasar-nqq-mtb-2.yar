rule Trojan_BAT_Quasar_NQQ_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.NQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8c 31 00 00 01 a2 11 07 18 08 28 ?? 00 00 0a a2 11 07 13 06 11 06 14 14 19 8d ?? 00 00 01 13 08 11 08 16 17 9c 11 08 17 16 9c 11 08 18 17 9c 11 08 17 28 ?? 00 00 0a } 		$a_01_1 = {4e 61 6e 79 73 65 78 72 66 6d 71 66 75 69 6b 70 64 6b 68 71 62 6e 65 67 73 6b 76 7a } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}