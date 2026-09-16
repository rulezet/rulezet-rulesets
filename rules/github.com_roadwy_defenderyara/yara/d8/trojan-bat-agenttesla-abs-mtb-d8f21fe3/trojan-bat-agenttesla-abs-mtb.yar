rule Trojan_BAT_AgentTesla_ABS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 38 1f fb ff ff 12 08 28 ?? 00 00 0a 12 08 28 ?? 00 00 0a 17 62 58 12 08 28 ?? 00 00 0a 18 62 58 13 14 11 14 06 7b ?? 00 00 04 20 ?? 00 00 00 5f 61 13 14 11 1c } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}