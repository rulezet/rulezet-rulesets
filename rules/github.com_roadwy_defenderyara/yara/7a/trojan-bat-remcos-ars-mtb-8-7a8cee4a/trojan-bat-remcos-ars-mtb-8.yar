rule Trojan_BAT_Remcos_ARS_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0a 12 0a 28 ?? 01 00 0a 13 0b 12 0a 28 ?? 01 00 0a 13 0c 12 0a 28 ?? 01 00 0a 13 0d 08 11 0b 6f ?? 01 00 06 13 0b 08 11 0c 6f ?? 01 00 06 13 0c 08 11 0d 6f ?? 01 00 06 13 0d 11 0b 06 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}