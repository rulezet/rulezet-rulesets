rule Trojan_BAT_Remcos_ARO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 06 03 17 59 28 ?? 00 00 06 0b 02 06 03 28 ?? 00 00 06 0c 02 07 06 8e 69 58 28 ?? 00 00 2b 08 07 59 06 8e 69 59 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}