rule Trojan_BAT_Quasar_NAS_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.NAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 72 ?? 00 00 70 02 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 02 6f ?? 00 00 0a 0b 25 07 28 ?? 00 00 0a 28 17 00 00 0a } 		$a_01_1 = {71 00 61 00 7a 00 77 00 73 00 78 00 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}