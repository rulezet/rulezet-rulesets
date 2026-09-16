rule Trojan_BAT_Remcos_ARM_MTB_14{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0b 2b 5f 00 11 05 17 58 20 ff 00 00 00 5f 13 05 11 06 11 04 11 05 95 58 20 ff 00 00 00 5f 13 06 02 11 04 11 05 8f ?? 00 00 01 11 04 11 06 8f ?? 00 00 01 28 ?? 00 00 06 00 11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0c 02 11 0b 07 09 11 04 11 0c 28 ?? 00 00 06 00 00 11 0b 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}