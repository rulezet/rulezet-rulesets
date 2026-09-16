rule Trojan_BAT_Remcos_GWT_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.GWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 14 0c 2b 2f } 		$a_03_1 = {de 03 26 de 00 73 ?? 00 00 0a 72 ?? 00 00 70 } 		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 33 00 2e 00 31 00 36 00 30 00 2e 00 33 00 32 00 2e 00 34 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}