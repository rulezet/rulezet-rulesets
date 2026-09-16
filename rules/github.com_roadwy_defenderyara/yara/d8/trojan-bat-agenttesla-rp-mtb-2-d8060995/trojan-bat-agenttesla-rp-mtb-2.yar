rule Trojan_BAT_AgentTesla_RP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 17 8d 5d 00 00 01 25 16 1f 7c 9d 28 1f 01 00 06 0a 07 ?? ?? ?? ?? ?? 5a ?? ?? ?? ?? ?? 61 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}