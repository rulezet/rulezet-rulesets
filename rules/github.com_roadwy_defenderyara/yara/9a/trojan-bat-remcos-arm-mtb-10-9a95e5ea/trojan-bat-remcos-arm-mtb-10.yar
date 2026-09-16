rule Trojan_BAT_Remcos_ARM_MTB_10{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 17 2b 63 00 11 06 17 58 20 ff 00 00 00 5f 13 06 11 05 11 04 11 06 95 58 20 ff 00 00 00 5f 13 05 02 11 04 11 06 8f 7d 00 00 01 11 04 11 05 8f 7d 00 00 01 28 ?? 00 00 06 00 11 04 11 06 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 18 09 11 17 07 11 17 91 11 04 11 18 95 61 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}