rule Trojan_BAT_Remcos_ARO_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7a 06 16 07 06 8e 69 28 ?? 00 00 0a 07 06 8e 69 1f 10 12 02 28 } 		$a_03_1 = {0c 08 07 17 73 1f 00 00 0a 0d 02 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 13 05 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}