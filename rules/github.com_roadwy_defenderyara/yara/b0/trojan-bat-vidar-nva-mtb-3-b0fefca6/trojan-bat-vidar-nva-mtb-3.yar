rule Trojan_BAT_Vidar_NVA_MTB_3{
	meta:
		description = "Trojan:BAT/Vidar.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 07 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 02 1f 30 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 73 ?? 00 00 0a 28 ?? 00 00 06 03 6f ?? 00 00 0a 28 ?? 00 00 06 0c 08 73 ?? 00 00 0a 07 06 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 28 ?? 00 00 2b 16 fe 01 } 		$a_01_1 = {62 6f 75 6c 69 6e 67 34 66 65 65 74 5f 6d 65 6d 62 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}