rule Trojan_BAT_Quasar_NQQ_MTB_3{
	meta:
		description = "Trojan:BAT/Quasar.NQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 28 19 00 00 0a 28 ?? 00 00 0a 0b 07 07 06 25 13 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a } 		$a_01_1 = {43 6c 69 65 6e 74 2d 62 75 69 6c 74 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}