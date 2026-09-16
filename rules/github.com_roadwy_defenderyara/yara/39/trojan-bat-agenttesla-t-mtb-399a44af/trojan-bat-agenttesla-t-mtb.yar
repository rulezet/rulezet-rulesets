rule Trojan_BAT_AgentTesla_T_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 0a 02 06 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 7e ?? ?? ?? 04 03 1f 10 5d 91 61 d2 81 ?? ?? ?? 01 02 06 91 0b 2b 00 07 2a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}