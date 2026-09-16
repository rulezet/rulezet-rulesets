rule Trojan_BAT_Quasar_NQA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 28 fd 00 00 0a 03 04 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 06 6f ?? 01 00 0a 2a } 		$a_03_1 = {02 7b 45 00 00 04 02 02 7b ?? 00 00 04 03 28 ?? 00 00 06 6f ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 17 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}