rule Trojan_BAT_AgentTesla_AQG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 17 2d 03 26 2b 03 0c 2b 00 73 ?? ?? ?? 0a 0d 08 09 28 ?? ?? ?? 06 09 16 6a 6f ?? ?? ?? 0a 09 13 04 de 19 08 6f ?? ?? ?? 0a dc } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}