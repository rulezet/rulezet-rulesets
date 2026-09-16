rule Trojan_BAT_Zusy_AZY_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 16 0c 2b 1a 06 08 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 16 61 d2 81 ?? 00 00 01 08 17 58 0c 08 06 8e 69 32 e0 07 06 28 ?? 00 00 0a 07 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}