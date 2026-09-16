rule Trojan_BAT_AgentTesla_RP_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 2b 0b 00 70 0b 28 df 00 00 0a 72 ?? ?? ?? 70 18 17 8d 21 00 00 01 25 16 07 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}