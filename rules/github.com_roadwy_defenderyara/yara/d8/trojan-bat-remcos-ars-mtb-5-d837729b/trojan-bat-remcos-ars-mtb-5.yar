rule Trojan_BAT_Remcos_ARS_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d ?? 00 00 01 0a 16 0b 38 ?? 00 00 00 06 07 02 07 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}