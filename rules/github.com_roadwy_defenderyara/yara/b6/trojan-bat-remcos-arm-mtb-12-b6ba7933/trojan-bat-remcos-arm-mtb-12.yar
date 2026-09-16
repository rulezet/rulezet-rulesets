rule Trojan_BAT_Remcos_ARM_MTB_12{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 12 29 28 ?? 00 00 0a 58 13 0a 11 0b 12 29 28 ?? 00 00 0a 58 13 0b 11 0c 12 29 28 ?? 00 00 0a 58 13 0c 12 29 28 ?? 00 00 0a 12 29 28 ?? 00 00 0a 58 12 29 28 ?? 00 00 0a 58 13 2a 11 2a 11 0d 31 04 11 2a 13 0d 11 2a 11 0e 2f 04 11 2a 13 0e 11 27 11 07 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}