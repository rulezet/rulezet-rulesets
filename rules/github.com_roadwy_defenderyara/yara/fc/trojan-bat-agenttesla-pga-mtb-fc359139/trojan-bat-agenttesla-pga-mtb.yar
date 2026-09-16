rule Trojan_BAT_Agenttesla_PGA_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 05 0e 04 6f ?? 00 00 0a 0a 06 0e 05 28 ?? 00 00 06 0b 04 03 6f ?? 00 00 0a 59 0c 08 19 32 0a 03 07 0e 05 28 ?? 00 00 06 2a } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}