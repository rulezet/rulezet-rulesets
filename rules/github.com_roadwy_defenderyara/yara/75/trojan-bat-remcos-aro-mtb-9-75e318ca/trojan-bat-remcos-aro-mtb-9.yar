rule Trojan_BAT_Remcos_ARO_MTB_9{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 2a 00 38 00 00 00 00 00 72 51 00 00 70 28 ?? ?? ?? 06 13 00 38 00 00 00 00 28 } 		$a_03_1 = {02 8e 69 17 59 13 01 20 01 00 00 00 7e 61 04 00 04 7b b5 04 00 04 39 ?? ?? ?? ff 26 20 01 00 00 00 38 ?? ?? ?? ff 11 03 17 58 13 03 38 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}