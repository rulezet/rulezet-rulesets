rule Trojan_BAT_Remcos_ARM_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 30 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}