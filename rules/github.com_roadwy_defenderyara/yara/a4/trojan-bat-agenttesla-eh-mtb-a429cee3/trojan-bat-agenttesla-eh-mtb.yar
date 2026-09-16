rule Trojan_BAT_AgentTesla_EH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 1f 18 fe 01 2c 19 07 07 8e 69 17 63 8f ?? ?? ?? ?? 25 47 06 1a 58 4a d2 61 d2 52 1f 19 13 0a } 	condition:
		((#a_03_0  & 1)*6) >=6
 
}