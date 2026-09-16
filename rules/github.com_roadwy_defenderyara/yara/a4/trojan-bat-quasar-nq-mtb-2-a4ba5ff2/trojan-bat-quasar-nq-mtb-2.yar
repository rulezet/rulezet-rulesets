rule Trojan_BAT_Quasar_NQ_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 8d 01 00 00 01 25 16 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 75 ?? 00 00 01 14 6f ?? 00 00 0a 75 ?? 00 00 1b } 		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 39 35 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}