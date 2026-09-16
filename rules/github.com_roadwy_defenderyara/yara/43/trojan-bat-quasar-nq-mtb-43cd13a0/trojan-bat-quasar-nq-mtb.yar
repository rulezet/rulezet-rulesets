rule Trojan_BAT_Quasar_NQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 6f 65 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 06 28 ?? 00 00 06 0d 28 ?? 00 00 06 09 } 		$a_01_1 = {62 72 61 76 65 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}