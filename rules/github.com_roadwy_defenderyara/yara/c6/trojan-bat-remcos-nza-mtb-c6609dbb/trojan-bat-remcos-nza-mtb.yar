rule Trojan_BAT_Remcos_NZA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 } 		$a_01_1 = {62 00 cc 06 59 00 46 06 86 06 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}